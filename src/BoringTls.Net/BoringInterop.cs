using System.Runtime.InteropServices;

namespace BoringTls.Net;

/// <summary>
/// BoringSSL P/Invoke 声明 — 最小子集，仅包含 TLS 客户端握手所需的 API
/// </summary>
internal static partial class BoringInterop
{
    // 使用 'b' 前缀避免与系统 OpenSSL 的 libssl/libcrypto 冲突
    private const string LibSsl = "libbssl";
    private const string LibCrypto = "libbcrypto";

    /// <summary>
    /// 静态构造函数 — 在任何 P/Invoke 调用前预加载 BoringSSL 原生库
    /// </summary>
    static BoringInterop()
    {
        // 必须先加载 libbcrypto（libbssl 依赖它）
        PreloadLibrary(LibCrypto);
        PreloadLibrary(LibSsl);
    }

    private static void PreloadLibrary(string libraryName)
    {
        var rid = RuntimeInformation.RuntimeIdentifier;
        var assemblyDir = Path.GetDirectoryName(typeof(BoringInterop).Assembly.Location) ?? ".";
        var baseDir = AppContext.BaseDirectory;

        // 按优先级搜索（覆盖 macOS、Linux、Windows）
        string[] candidates =
        [
            Path.Combine(baseDir, $"{libraryName}.dylib"),
            Path.Combine(baseDir, $"{libraryName}.so"),
            Path.Combine(baseDir, $"{libraryName}.dll"),
            Path.Combine(assemblyDir, $"{libraryName}.dylib"),
            Path.Combine(assemblyDir, $"{libraryName}.so"),
            Path.Combine(assemblyDir, $"{libraryName}.dll"),
            Path.Combine(baseDir, rid, "native", $"{libraryName}.dylib"),
            Path.Combine(assemblyDir, rid, "native", $"{libraryName}.dylib"),
            Path.Combine(baseDir, "runtimes", rid, "native", $"{libraryName}.dylib"),
            Path.Combine(assemblyDir, "runtimes", rid, "native", $"{libraryName}.dylib"),
            Path.Combine(baseDir, "runtimes", rid, "native", $"{libraryName}.so"),
            Path.Combine(assemblyDir, "runtimes", rid, "native", $"{libraryName}.so"),
            Path.Combine(baseDir, "runtimes", rid, "native", $"{libraryName}.dll"),
            Path.Combine(assemblyDir, "runtimes", rid, "native", $"{libraryName}.dll"),
        ];

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out _))
                return;
        }

        // 最后一搏：让系统默认搜索
        NativeLibrary.TryLoad(libraryName, out _);
    }

    // ============ SSL_CTX 生命周期 ============

    [LibraryImport(LibSsl, EntryPoint = "TLS_client_method")]
    internal static partial nint TLS_client_method();

    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_new")]
    internal static partial nint SSL_CTX_new(nint method);

    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_free")]
    internal static partial void SSL_CTX_free(nint ctx);

    // ============ SSL 对象 ============

    [LibraryImport(LibSsl, EntryPoint = "SSL_new")]
    internal static partial nint SSL_new(nint ctx);

    [LibraryImport(LibSsl, EntryPoint = "SSL_free")]
    internal static partial void SSL_free(nint ssl);

    [LibraryImport(LibSsl, EntryPoint = "SSL_set_connect_state")]
    internal static partial void SSL_set_connect_state(nint ssl);

    [LibraryImport(LibSsl, EntryPoint = "SSL_do_handshake")]
    internal static partial int SSL_do_handshake(nint ssl);

    [LibraryImport(LibSsl, EntryPoint = "SSL_get_error")]
    internal static partial int SSL_get_error(nint ssl, int ret);

    // ============ BIO (I/O 抽象) ============

    [LibraryImport(LibCrypto, EntryPoint = "BIO_s_mem")]
    internal static partial nint BIO_s_mem();

    [LibraryImport(LibCrypto, EntryPoint = "BIO_new")]
    internal static partial nint BIO_new(nint type);

    [LibraryImport(LibSsl, EntryPoint = "SSL_set_bio")]
    internal static partial void SSL_set_bio(nint ssl, nint rbio, nint wbio);

    [LibraryImport(LibCrypto, EntryPoint = "BIO_write")]
    internal static partial int BIO_write(nint bio, ref byte data, int len);

    [LibraryImport(LibCrypto, EntryPoint = "BIO_read")]
    internal static partial int BIO_read(nint bio, ref byte buf, int len);

    [LibraryImport(LibCrypto, EntryPoint = "BIO_ctrl_pending")]
    internal static partial nuint BIO_ctrl_pending(nint bio);

    // ============ 数据传输 ============

    [LibraryImport(LibSsl, EntryPoint = "SSL_read")]
    internal static partial int SSL_read(nint ssl, ref byte buf, int num);

    [LibraryImport(LibSsl, EntryPoint = "SSL_write")]
    internal static partial int SSL_write(nint ssl, ref byte buf, int num);

    /// <summary>查询握手后协商的 ALPN 协议</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_get0_alpn_selected")]
    internal static partial void SSL_get0_alpn_selected(nint ssl, out nint data, out int len);

    // ============ ★ 指纹控制 — TLS ClientHello 参数 ============

    /// <summary>设置 cipher suite 列表（BoringSSL 统一管理 TLS 1.2/1.3）</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set_cipher_list", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SSL_CTX_set_cipher_list(nint ctx, string str);

    /// <summary>设置 signature algorithms</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set1_sigalgs_list", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SSL_CTX_set1_sigalgs_list(nint ctx, string str);

    /// <summary>设置 supported groups/curves</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set1_curves_list", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SSL_CTX_set1_curves_list(nint ctx, string str);

    /// <summary>设置 ALPN 协议</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_set_alpn_protos")]
    internal static partial int SSL_set_alpn_protos(nint ssl, ref byte protos, int protosLen);

    /// <summary>设置 SNI (Server Name Indication)</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_set_tlsext_host_name", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int SSL_set_tlsext_host_name(nint ssl, string name);

    /// <summary>★ BoringSSL 特有：启用/禁用 GREASE（CTX 级别）</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set_grease_enabled")]
    internal static partial void SSL_CTX_set_grease_enabled(nint ctx, int enabled);

    /// <summary>★ BoringSSL 特有：控制 extension 随机排列（CTX 级别）</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set_permute_extensions")]
    internal static partial void SSL_CTX_set_permute_extensions(nint ctx, int enabled);

    /// <summary>设置最小 TLS 版本</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set_min_proto_version")]
    internal static partial int SSL_CTX_set_min_proto_version(nint ctx, ushort version);

    /// <summary>设置最大 TLS 版本</summary>
    [LibraryImport(LibSsl, EntryPoint = "SSL_CTX_set_max_proto_version")]
    internal static partial int SSL_CTX_set_max_proto_version(nint ctx, ushort version);

    // ============ 错误处理 ============

    [LibraryImport(LibCrypto, EntryPoint = "ERR_get_error")]
    internal static partial ulong ERR_get_error();

    [LibraryImport(LibCrypto, EntryPoint = "ERR_error_string")]
    internal static partial nint ERR_error_string(ulong e, nint buf);

    // ============ 常量 ============

    internal const int SSL_ERROR_NONE = 0;
    internal const int SSL_ERROR_SSL = 1;
    internal const int SSL_ERROR_WANT_READ = 2;
    internal const int SSL_ERROR_WANT_WRITE = 3;
    internal const int SSL_ERROR_SYSCALL = 5;
    internal const int SSL_ERROR_ZERO_RETURN = 6;

    internal const ushort TLS1_VERSION = 0x0301;
    internal const ushort TLS1_1_VERSION = 0x0302;
    internal const ushort TLS1_2_VERSION = 0x0303;
    internal const ushort TLS1_3_VERSION = 0x0304;

    // ============ 辅助方法 ============

    /// <summary>构建 ALPN 协议列表的二进制格式</summary>
    internal static byte[] BuildAlpnProtos(params string[] protocols)
    {
        var result = new List<byte>();
        foreach (var proto in protocols)
        {
            result.Add((byte)proto.Length);
            result.AddRange(System.Text.Encoding.ASCII.GetBytes(proto));
        }
        return result.ToArray();
    }

    /// <summary>获取最后一个 BoringSSL 错误的描述</summary>
    internal static string GetLastError()
    {
        var err = ERR_get_error();
        if (err == 0) return "no error";
        var ptr = ERR_error_string(err, 0);
        return Marshal.PtrToStringAnsi(ptr) ?? "unknown error";
    }
}
