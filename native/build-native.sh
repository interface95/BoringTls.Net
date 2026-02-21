#!/bin/bash
# BoringSSL 跨平台编译脚本
# 使用 Docker 编译 Linux，本地编译 macOS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNTIMES_DIR="$SCRIPT_DIR/runtimes"
BORING_REPO="https://boringssl.googlesource.com/boringssl"
BUILD_DIR="/tmp/boringssl-build"

# 编译产物重命名（避免与系统 libssl/libcrypto 冲突）
SSL_NAME="libbssl"
CRYPTO_NAME="libbcrypto"

build_linux() {
    local arch=$1  # amd64 or arm64
    local rid="linux-${arch/amd64/x64}"
    local platform="linux/${arch}"

    echo "=== 编译 ${rid} ==="
    mkdir -p "$RUNTIMES_DIR/${rid}/native"

    docker run --rm --platform "$platform" \
        -v "$RUNTIMES_DIR/${rid}/native:/output" \
        ubuntu:24.04 bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq git cmake ninja-build gcc g++ golang-go > /dev/null 2>&1
        git clone --depth=1 $BORING_REPO /tmp/boringssl
        cd /tmp/boringssl
        mkdir build && cd build
        cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=1 ..
        ninja ssl crypto
        cp ssl/libssl.so /output/${SSL_NAME}.so
        cp crypto/libcrypto.so /output/${CRYPTO_NAME}.so
        echo '=== done ==='
    "

    # 修复内部链接（Linux 用 SONAME）
    echo "✅ ${rid} 完成: $(ls "$RUNTIMES_DIR/${rid}/native/")"
}

build_macos() {
    local arch=$1  # arm64 or x86_64
    local rid="osx-${arch/x86_64/x64}"

    echo "=== 编译 ${rid} ==="
    mkdir -p "$RUNTIMES_DIR/${rid}/native"

    # 检查是否已有
    if [ -f "$RUNTIMES_DIR/${rid}/native/${SSL_NAME}.dylib" ]; then
        echo "⏭️  ${rid} 已存在，跳过"
        return
    fi

    local tmpdir="/tmp/boringssl-${arch}"
    rm -rf "$tmpdir"
    git clone --depth=1 "$BORING_REPO" "$tmpdir"
    cd "$tmpdir"
    mkdir build && cd build
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=1 \
        -DCMAKE_OSX_ARCHITECTURES="$arch" \
        ..
    ninja ssl crypto

    cp ssl/libssl.dylib "$RUNTIMES_DIR/${rid}/native/${SSL_NAME}.dylib"
    cp crypto/libcrypto.dylib "$RUNTIMES_DIR/${rid}/native/${CRYPTO_NAME}.dylib"

    # 修复内部链接
    cd "$RUNTIMES_DIR/${rid}/native"
    install_name_tool -id "@loader_path/${SSL_NAME}.dylib" "${SSL_NAME}.dylib"
    install_name_tool -change "@rpath/libcrypto.dylib" "@loader_path/${CRYPTO_NAME}.dylib" "${SSL_NAME}.dylib"
    install_name_tool -id "@loader_path/${CRYPTO_NAME}.dylib" "${CRYPTO_NAME}.dylib"

    echo "✅ ${rid} 完成: $(ls "$RUNTIMES_DIR/${rid}/native/")"
}

build_windows() {
    echo "=== 编译 win-x64 (Docker + MinGW) ==="
    mkdir -p "$RUNTIMES_DIR/win-x64/native"

    docker run --rm --platform linux/amd64 \
        -v "$RUNTIMES_DIR/win-x64/native:/output" \
        ubuntu:24.04 bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq git cmake ninja-build golang-go \
            gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 > /dev/null 2>&1

        git clone --depth=1 $BORING_REPO /tmp/boringssl
        cd /tmp/boringssl
        mkdir build && cd build

        cat > /tmp/mingw-toolchain.cmake << 'EOF'
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF

        cmake -GNinja \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=1 \
            -DCMAKE_TOOLCHAIN_FILE=/tmp/mingw-toolchain.cmake \
            ..
        ninja ssl crypto

        cp ssl/libssl.dll /output/${SSL_NAME}.dll 2>/dev/null || cp ssl/ssl.dll /output/${SSL_NAME}.dll
        cp crypto/libcrypto.dll /output/${CRYPTO_NAME}.dll 2>/dev/null || cp crypto/crypto.dll /output/${CRYPTO_NAME}.dll
        echo '=== done ==='
    "
    echo "✅ win-x64 完成: $(ls "$RUNTIMES_DIR/win-x64/native/")"
}

# ============ 主流程 ============

case "${1:-all}" in
    linux-x64)   build_linux amd64 ;;
    linux-arm64) build_linux arm64 ;;
    osx-arm64)   build_macos arm64 ;;
    osx-x64)     build_macos x86_64 ;;
    win-x64)     build_windows ;;
    all)
        build_linux amd64
        build_linux arm64
        build_windows
        build_macos arm64
        ;;
    *)
        echo "用法: $0 [linux-x64|linux-arm64|osx-arm64|osx-x64|win-x64|all]"
        exit 1
        ;;
esac

echo ""
echo "=== 编译完成 ==="
find "$RUNTIMES_DIR" -type f \( -name "*.dylib" -o -name "*.so" -o -name "*.dll" \) -exec ls -lh {} \;
