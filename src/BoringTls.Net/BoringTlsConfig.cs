namespace BoringTls.Net;

/// <summary>
/// BoringSSL TLS 指纹配置 — 精确控制 ClientHello 的每个参数
/// </summary>
public sealed record BoringTlsConfig
{
    /// <summary>Cipher suite 列表（OpenSSL 字符串格式，冒号分隔）。
    /// BoringSSL 用 cipher_list 统一管理 TLS 1.2 和 1.3。</summary>
    public string CipherList { get; init; } = "";

    /// <summary>Signature algorithms（冒号分隔）</summary>
    public string SigAlgs { get; init; } = "";

    /// <summary>Supported groups/curves（冒号分隔）</summary>
    public string Curves { get; init; } = "";

    /// <summary>ALPN 协议列表</summary>
    public string[] AlpnProtos { get; init; } = [];

    /// <summary>最小 TLS 版本（0 = BoringSSL 默认，不限制）</summary>
    public ushort MinVersion { get; init; }

    /// <summary>最大 TLS 版本（0 = BoringSSL 默认，不限制）</summary>
    public ushort MaxVersion { get; init; }

    /// <summary>是否启用 GREASE（Chrome=true, Go=false）</summary>
    public bool GreaseEnabled { get; init; }

    /// <summary>是否随机排列 extensions（Chrome=true, Go=false）</summary>
    public bool PermuteExtensions { get; init; }

    /// <summary>
    /// Go crypto/tls 默认指纹配置 — 与 Rust tls.rs 完全对齐
    /// </summary>
    public static BoringTlsConfig GoDefault { get; } = new()
    {
        // ★ TLS 1.3 ciphers（Go 硬编码，必须在前面）+ TLS 1.2 ciphers
        CipherList = string.Join(":",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "AES256-SHA"),

        // ★ 与 Rust GO_SIGALGS 完全一致（BoringSSL 格式）
        SigAlgs = string.Join(":",
            "ECDSA+SHA256",
            "RSA-PSS+SHA256",
            "RSA+SHA256",
            "ECDSA+SHA384",
            "RSA-PSS+SHA384",
            "RSA+SHA384",
            "RSA-PSS+SHA512",
            "RSA+SHA512",
            "RSA+SHA1"),

        // ★ Go 默认只有 3 个 curve（无 P-521）
        Curves = "X25519:P-256:P-384",
        AlpnProtos = ["h2", "http/1.1"],
        GreaseEnabled = false,
        PermuteExtensions = false,
    };

    /// <summary>
    /// Chrome 142 指纹配置
    /// </summary>
    public static BoringTlsConfig Chrome142 { get; } = new()
    {
        CipherList = string.Join(":",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "AES256-SHA"),

        SigAlgs = string.Join(":",
            "ecdsa_secp256r1_sha256",
            "rsa_pss_rsae_sha256",
            "rsa_pkcs1_sha256",
            "ecdsa_secp384r1_sha384",
            "rsa_pss_rsae_sha384",
            "rsa_pkcs1_sha384",
            "rsa_pss_rsae_sha512",
            "rsa_pkcs1_sha512"),

        Curves = "X25519:P-256:P-384",
        AlpnProtos = ["h2", "http/1.1"],
        GreaseEnabled = true,
        PermuteExtensions = true,
    };
}
