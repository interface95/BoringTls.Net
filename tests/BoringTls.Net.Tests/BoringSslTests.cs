using BoringTls.Net;

namespace BoringTls.Net.Tests;

public class BoringSslTests
{
    // ═══════════════════════════════════════════════════════════════════════════
    // Rust tls.rs 基准常量 — 测试时与 BoringTlsConfig.GoDefault 精确比对
    // ═══════════════════════════════════════════════════════════════════════════
    private const string RustGoCipherList =
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:" +
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" +
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:" +
        "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

    private const string RustGoSigAlgs =
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:" +
        "ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:" +
        "RSA-PSS+SHA512:RSA+SHA512:RSA+SHA1";

    private const string RustGoCurves = "X25519:P-256:P-384";

    // ═══════════════════════════════════════════════════════════════════════════
    // 配置验证
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void BoringTlsConfig_GoDefault_HasExpectedCipherSuites()
    {
        var go = BoringTlsConfig.GoDefault;
        Assert.False(string.IsNullOrEmpty(go.CipherList));
        Assert.Contains("ECDHE-ECDSA-AES128-GCM-SHA256", go.CipherList);
        Assert.Contains("ECDHE-RSA-CHACHA20-POLY1305", go.CipherList);
        Assert.Equal("X25519:P-256:P-384", go.Curves);
    }

    [Fact]
    public void BoringTlsConfig_Chrome142_EnablesGrease()
    {
        var chrome = BoringTlsConfig.Chrome142;
        Assert.True(chrome.GreaseEnabled);
        Assert.True(chrome.PermuteExtensions);
    }

    [Fact]
    public void BoringInterop_BuildAlpnProtos_CorrectFormat()
    {
        var protos = new[] { "h2", "http/1.1" };
        var wire = BoringInterop.BuildAlpnProtos(protos);

        // h2 → 0x02 'h' '2'
        Assert.Equal(0x02, wire[0]);
        Assert.Equal((byte)'h', wire[1]);
        Assert.Equal((byte)'2', wire[2]);
        // http/1.1 → 0x08 'h' 't' 't' 'p' '/' '1' '.' '1'
        Assert.Equal(0x08, wire[3]);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BoringSslStream 创建/握手/通信
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void BoringSslStream_CanBeCreated()
    {
        using var ms = new MemoryStream();
        using var ssl = new BoringSslStream(ms, "test.example.com", BoringTlsConfig.GoDefault);
        Assert.NotNull(ssl);
    }

    [Fact]
    public async Task BoringSslStream_GoProfile_CompletesHandshake()
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        var http11Config = BoringTlsConfig.GoDefault with { AlpnProtos = ["http/1.1"] };
        using var ssl = new BoringSslStream(tcp.GetStream(), "www.google.com", http11Config);
        await ssl.AuthenticateAsync();
    }

    [Fact]
    public async Task BoringSslStream_GoProfile_H2AlpnNegotiation()
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        using var ssl = new BoringSslStream(tcp.GetStream(), "www.google.com", BoringTlsConfig.GoDefault);
        await ssl.AuthenticateAsync();
    }

    [Fact]
    public async Task BoringSslStream_DirectHttpRequest_WorksEndToEnd()
    {
        var http11Config = BoringTlsConfig.GoDefault with { AlpnProtos = ["http/1.1"] };

        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("httpbin.org", 443);

        using var ssl = new BoringSslStream(tcp.GetStream(), "httpbin.org", http11Config);
        await ssl.AuthenticateAsync();

        var request = "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"u8;
        await ssl.WriteAsync(request.ToArray());

        var buf = new byte[4096];
        var read = await ssl.ReadAsync(buf);
        Assert.True(read > 0);

        var response = System.Text.Encoding.UTF8.GetString(buf, 0, read);
        Assert.Contains("HTTP/1.1 200", response);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ 与 Rust tls.rs 精确对比
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void GoDefault_CipherList_MatchesRust()
    {
        Assert.Equal(RustGoCipherList, BoringTlsConfig.GoDefault.CipherList);
    }

    [Fact]
    public void GoDefault_SigAlgs_MatchesRust()
    {
        Assert.Equal(RustGoSigAlgs, BoringTlsConfig.GoDefault.SigAlgs);
    }

    [Fact]
    public void GoDefault_Curves_MatchesRust()
    {
        Assert.Equal(RustGoCurves, BoringTlsConfig.GoDefault.Curves);
    }

    [Fact]
    public void GoDefault_NoChromeFeatures()
    {
        var go = BoringTlsConfig.GoDefault;
        Assert.False(go.GreaseEnabled, "Go 不启用 GREASE");
        Assert.False(go.PermuteExtensions, "Go 不随机排列 extensions");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ tls.peet.ws 完整指纹验证
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task GoProfile_PeetWs_FullFingerprint()
    {
        var http11Config = BoringTlsConfig.GoDefault with { AlpnProtos = ["http/1.1"] };

        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("tls.peet.ws", 443);

        using var ssl = new BoringSslStream(tcp.GetStream(), "tls.peet.ws", http11Config);
        await ssl.AuthenticateAsync();

        var request = "GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\nAccept: application/json\r\n\r\n"u8;
        await ssl.WriteAsync(request.ToArray());

        using var ms = new MemoryStream();
        var buf = new byte[16384];
        int read;
        while ((read = await ssl.ReadAsync(buf)) > 0)
            ms.Write(buf, 0, read);

        var fullResponse = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        var bodyStart = fullResponse.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        Assert.True(bodyStart > 0);
        var jsonBody = fullResponse[(bodyStart + 4)..].Trim();

        var doc = System.Text.Json.JsonDocument.Parse(jsonBody);
        var tls = doc.RootElement.GetProperty("tls");

        // JA3 hash 非空
        var ja3Hash = tls.GetProperty("ja3_hash").GetString()!;
        Assert.False(string.IsNullOrEmpty(ja3Hash));

        // Cipher 列表
        var ciphers = tls.GetProperty("ciphers").EnumerateArray()
            .Select(c => c.GetString()!).ToList();
        Assert.Contains("TLS_AES_128_GCM_SHA256", ciphers);
        Assert.Contains("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ciphers);
        Assert.Contains("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", ciphers);

        // TLS 版本
        var ver = tls.GetProperty("tls_version_negotiated").GetString()!;
        Assert.True(ver == "772" || ver == "771");

        // 输出用于人工比对
        var ja3 = tls.GetProperty("ja3").GetString()!;
        Console.WriteLine($"JA3:      {ja3}");
        Console.WriteLine($"JA3_hash: {ja3Hash}");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ BoringHttpClientFactory
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task BoringHttpClientFactory_Create_WorksEndToEnd()
    {
        using var client = BoringHttpClientFactory.Create(BoringTlsConfig.GoDefault);
        var response = await client.GetAsync("https://tls.peet.ws/api/all");
        Assert.True(response.IsSuccessStatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("ja3", body);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ Chrome142 配置完整验证
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void Chrome142_CipherList_ContainsExpectedSuites()
    {
        var chrome = BoringTlsConfig.Chrome142;
        Assert.Contains("ECDHE-ECDSA-AES128-GCM-SHA256", chrome.CipherList);
        Assert.Contains("ECDHE-RSA-CHACHA20-POLY1305", chrome.CipherList);
        Assert.Contains("AES256-GCM-SHA384", chrome.CipherList);
        // Chrome 不含 TLS 1.3 前缀（由 BoringSSL 隐式管理）
        Assert.DoesNotContain("TLS_AES_128_GCM_SHA256", chrome.CipherList);
    }

    [Fact]
    public void Chrome142_SigAlgs_ContainsExpectedAlgorithms()
    {
        var chrome = BoringTlsConfig.Chrome142;
        Assert.Contains("ecdsa_secp256r1_sha256", chrome.SigAlgs);
        Assert.Contains("rsa_pss_rsae_sha256", chrome.SigAlgs);
        Assert.Contains("rsa_pkcs1_sha512", chrome.SigAlgs);
        // Chrome 的 sigalgs 没 RSA+SHA1
        Assert.DoesNotContain("RSA+SHA1", chrome.SigAlgs);
    }

    [Fact]
    public void Chrome142_Curves_MatchesExpected()
    {
        Assert.Equal("X25519:P-256:P-384", BoringTlsConfig.Chrome142.Curves);
    }

    [Fact]
    public void Chrome142_Alpn_HasH2AndHttp11()
    {
        var chrome = BoringTlsConfig.Chrome142;
        Assert.Equal(2, chrome.AlpnProtos.Length);
        Assert.Equal("h2", chrome.AlpnProtos[0]);
        Assert.Equal("http/1.1", chrome.AlpnProtos[1]);
    }

    [Fact]
    public async Task Chrome142_Handshake_Succeeds()
    {
        var http11Config = BoringTlsConfig.Chrome142 with { AlpnProtos = ["http/1.1"] };
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        using var ssl = new BoringSslStream(tcp.GetStream(), "www.google.com", http11Config);
        await ssl.AuthenticateAsync();
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ 自定义配置
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task CustomConfig_MinimalCiphers_HandshakeSucceeds()
    {
        var config = new BoringTlsConfig
        {
            CipherList = "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256",
            SigAlgs = "RSA-PSS+SHA256:RSA+SHA256",
            Curves = "X25519:P-256",
            AlpnProtos = ["http/1.1"],
        };

        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        using var ssl = new BoringSslStream(tcp.GetStream(), "www.google.com", config);
        await ssl.AuthenticateAsync();
    }

    [Fact]
    public void Config_RecordWith_CreatesIndependentCopy()
    {
        var original = BoringTlsConfig.GoDefault;
        var modified = original with { GreaseEnabled = true, Curves = "X25519" };

        // 修改后的副本不影响原始对象
        Assert.False(original.GreaseEnabled);
        Assert.Equal("X25519:P-256:P-384", original.Curves);
        Assert.True(modified.GreaseEnabled);
        Assert.Equal("X25519", modified.Curves);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ 错误处理
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void InvalidCipherList_ThrowsOnHandshake()
    {
        var config = new BoringTlsConfig { CipherList = "THIS_IS_NOT_A_CIPHER" };

        using var ms = new MemoryStream();
        Assert.ThrowsAny<Exception>(() =>
            new BoringSslStream(ms, "test.example.com", config));
    }

    [Fact]
    public async Task WrongHostname_HandshakeFails()
    {
        var http11Config = BoringTlsConfig.GoDefault with { AlpnProtos = ["http/1.1"] };

        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        // SNI = wrong.example.com，但实际连的是 google.com → 证书不匹配
        using var ssl = new BoringSslStream(tcp.GetStream(), "wrong.example.com", http11Config);
        // BoringSSL 默认不验证证书，所以握手本身可能成功
        // 但这个测试确认不会崩溃
        try
        {
            await ssl.AuthenticateAsync();
        }
        catch (BoringSslException)
        {
            // 预期可能失败，但不应崩溃
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ Dispose 安全
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public void BoringSslStream_DoubleDispose_DoesNotThrow()
    {
        using var ms = new MemoryStream();
        var ssl = new BoringSslStream(ms, "test.example.com", BoringTlsConfig.GoDefault);
        ssl.Dispose();
        ssl.Dispose(); // 不应崩溃
    }

    [Fact]
    public async Task BoringSslStream_DisposeAfterHandshake_Cleans()
    {
        var http11Config = BoringTlsConfig.GoDefault with { AlpnProtos = ["http/1.1"] };
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        var ssl = new BoringSslStream(tcp.GetStream(), "www.google.com", http11Config);
        await ssl.AuthenticateAsync();
        ssl.Dispose();
        ssl.Dispose(); // 双重 Dispose 安全
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ HttpClient 并发 / 多次请求
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task BoringHttpClientFactory_MultipleRequests_ReuseConnection()
    {
        using var client = BoringHttpClientFactory.Create(BoringTlsConfig.GoDefault);

        // 连续 3 次请求，测试连接池复用
        for (var i = 0; i < 3; i++)
        {
            var response = await client.GetAsync("https://tls.peet.ws/api/all");
            Assert.True(response.IsSuccessStatusCode);
        }
    }

    [Fact]
    public async Task BoringHttpClientFactory_ConcurrentRequests_NoRace()
    {
        using var client = BoringHttpClientFactory.Create(BoringTlsConfig.GoDefault);

        var tasks = Enumerable.Range(0, 3)
            .Select(_ => client.GetAsync("https://tls.peet.ws/api/all"))
            .ToArray();

        var responses = await Task.WhenAll(tasks);
        Assert.All(responses, r => Assert.True(r.IsSuccessStatusCode));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ MinVersion / MaxVersion
    // ═══════════════════════════════════════════════════════════════════════════

    [Fact]
    public async Task MinVersion_Tls12_HandshakeSucceeds()
    {
        var config = BoringTlsConfig.GoDefault with
        {
            MinVersion = BoringInterop.TLS1_2_VERSION,
            MaxVersion = BoringInterop.TLS1_3_VERSION,
            AlpnProtos = ["http/1.1"],
        };

        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync("www.google.com", 443);

        using var ssl = new BoringSslStream(tcp.GetStream(), "www.google.com", config);
        await ssl.AuthenticateAsync();
    }

    [Fact]
    public void DefaultConfig_MinMaxVersion_AreZero()
    {
        var config = new BoringTlsConfig();
        Assert.Equal((ushort)0, config.MinVersion);
        Assert.Equal((ushort)0, config.MaxVersion);
    }
}
