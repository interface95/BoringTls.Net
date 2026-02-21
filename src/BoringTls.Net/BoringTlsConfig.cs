namespace BoringTls.Net;

/// <summary>
/// BoringSSL TLS 指纹配置 — 精确控制 ClientHello 的每个参数
/// </summary>
public sealed record BoringTlsConfig
{
    // ============ 基础指纹 ============

    /// <summary>Cipher suite 列表（OpenSSL 字符串格式，冒号分隔）</summary>
    public string CipherList { get; init; } = "";

    /// <summary>Signature algorithms（冒号分隔）</summary>
    public string SigAlgs { get; init; } = "";

    /// <summary>Supported groups/curves（冒号分隔）</summary>
    public string Curves { get; init; } = "";

    /// <summary>ALPN 协议列表</summary>
    public string[] AlpnProtos { get; init; } = [];

    /// <summary>最小 TLS 版本（0 = BoringSSL 默认）</summary>
    public ushort MinVersion { get; init; }

    /// <summary>最大 TLS 版本（0 = BoringSSL 默认）</summary>
    public ushort MaxVersion { get; init; }

    // ============ Chrome/Go 指纹开关 ============

    /// <summary>是否启用 GREASE（Chrome=true, Go=false）</summary>
    public bool GreaseEnabled { get; init; }

    /// <summary>是否随机排列 extensions（Chrome=true, Go=false）</summary>
    public bool PermuteExtensions { get; init; }

    // ============ ★ 高级指纹控制 ============

    /// <summary>ECH GREASE — 模拟 Encrypted Client Hello GREASE 扩展（Chrome=true）</summary>
    public bool EchGreaseEnabled { get; init; }

    /// <summary>SCT — 发送 signed_certificate_timestamp extension（Chrome=true）</summary>
    public bool SctEnabled { get; init; }

    /// <summary>OCSP Stapling — 发送 status_request extension（Chrome=true）</summary>
    public bool OcspStaplingEnabled { get; init; }

    /// <summary>证书压缩算法 ID 列表（Chrome 使用 Brotli=2）</summary>
    public ushort[] CertCompressionAlgIds { get; init; } = [];

    /// <summary>ALPS 协议列表（Chrome 发送空 ALPS settings 给 "h2"）</summary>
    public string[] AlpsProtocols { get; init; } = [];

    /// <summary>跳过证书验证（默认 true — 与 Go 和现有行为一致）</summary>
    public bool SkipCertVerification { get; init; } = true;

    // ═══════════════════════════════════════════════════════════════════════════
    // ★ 预设配置
    // ═══════════════════════════════════════════════════════════════════════════

    /// <summary>Go crypto/tls 默认指纹 — 与 Rust tls.rs 完全对齐</summary>
    public static BoringTlsConfig GoDefault { get; } = new()
    {
        CipherList = string.Join(":",
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA"),
        SigAlgs = string.Join(":",
            "ECDSA+SHA256", "RSA-PSS+SHA256", "RSA+SHA256",
            "ECDSA+SHA384", "RSA-PSS+SHA384", "RSA+SHA384",
            "RSA-PSS+SHA512", "RSA+SHA512", "RSA+SHA1"),
        Curves = "X25519:P-256:P-384",
        AlpnProtos = ["h2", "http/1.1"],
    };

    /// <summary>Chrome 142 指纹 — 包含全部 Chrome 特有 extensions</summary>
    public static BoringTlsConfig Chrome142 { get; } = new()
    {
        CipherList = string.Join(":",
            "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256", "AES256-GCM-SHA384", "AES128-SHA", "AES256-SHA"),
        SigAlgs = string.Join(":",
            "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"),
        Curves = "X25519:P-256:P-384",
        AlpnProtos = ["h2", "http/1.1"],
        GreaseEnabled = true,
        PermuteExtensions = true,
        EchGreaseEnabled = true,
        SctEnabled = true,
        OcspStaplingEnabled = true,
        CertCompressionAlgIds = [BoringInterop.TLSEXT_cert_compression_brotli],
        AlpsProtocols = ["h2"],
    };
}
