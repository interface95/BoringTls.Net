# BoringTls.Net

BoringSSL P/Invoke for .NET — 精确控制 TLS ClientHello 指纹 (JA3/JA4)

## 特性

- 🔐 **精确指纹控制** — CipherList、SigAlgs、Curves、ALPN、GREASE、Extension 排列
- 🎯 **内置 Go/Chrome 配置** — `BoringTlsConfig.GoDefault` / `BoringTlsConfig.Chrome142`
- 🌐 **HttpClient 工厂** — `BoringHttpClientFactory.Create()` 一行创建带指纹的 HttpClient
- 📦 **跨平台原生库** — macOS arm64、Linux x64/arm64、Windows x64

## 快速开始

```csharp
using BoringTls.Net;

// 使用 Go TLS 指纹
using var client = BoringHttpClientFactory.Create(BoringTlsConfig.GoDefault);
var response = await client.GetAsync("https://example.com");

// 使用 Chrome 142 指纹
using var chromeClient = BoringHttpClientFactory.Create(BoringTlsConfig.Chrome142);

// 自定义指纹
var config = new BoringTlsConfig
{
    CipherList = "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256",
    SigAlgs = "ECDSA+SHA256:RSA-PSS+SHA256",
    Curves = "X25519:P-256",
    AlpnProtos = ["h2", "http/1.1"],
    GreaseEnabled = false,
};
using var customClient = BoringHttpClientFactory.Create(config);
```

## 底层 API

```csharp
using var tcp = new TcpClient();
await tcp.ConnectAsync("example.com", 443);

using var ssl = new BoringSslStream(tcp.GetStream(), "example.com", BoringTlsConfig.GoDefault);
await ssl.AuthenticateAsync();

await ssl.WriteAsync("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"u8.ToArray());
```

## 编译原生库

```bash
# 全部平台
./native/build-native.sh all

# 单个平台
./native/build-native.sh osx-arm64
./native/build-native.sh linux-x64
```

## License

MIT
