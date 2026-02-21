using System.Runtime.InteropServices;

namespace BoringTls.Net;

/// <summary>
/// BoringSSL 支撑的 TLS Stream — 通过 P/Invoke 精确控制 ClientHello 指纹。
/// 使用 BIO memory 模式驱动握手，然后代理 SSL_read/SSL_write。
/// </summary>
public sealed class BoringSslStream : Stream
{
    private readonly Stream _inner;
    private nint _ctx;
    private nint _ssl;
    private nint _rbio;
    private nint _wbio;
    private bool _disposed;
    private bool _authenticated;

    private readonly byte[] _ioBuf = new byte[16384];

    public BoringSslStream(Stream innerStream, string host, BoringTlsConfig config)
    {
        _inner = innerStream ?? throw new ArgumentNullException(nameof(innerStream));

        // 创建 SSL_CTX
        var method = BoringInterop.TLS_client_method();
        _ctx = BoringInterop.SSL_CTX_new(method);
        if (_ctx == 0) throw new BoringSslException("SSL_CTX_new 失败");

        // TLS 版本范围（0 = 不限制，用 BoringSSL 默认）
        if (config.MinVersion > 0)
            BoringInterop.SSL_CTX_set_min_proto_version(_ctx, config.MinVersion);
        if (config.MaxVersion > 0)
            BoringInterop.SSL_CTX_set_max_proto_version(_ctx, config.MaxVersion);

        // ★ Cipher suites（BoringSSL 统一管理 TLS 1.2/1.3）
        if (!string.IsNullOrEmpty(config.CipherList))
        {
            if (BoringInterop.SSL_CTX_set_cipher_list(_ctx, config.CipherList) != 1)
                throw new BoringSslException($"SSL_CTX_set_cipher_list 失败: {BoringInterop.GetLastError()}");
        }

        // ★ Signature algorithms
        if (!string.IsNullOrEmpty(config.SigAlgs))
        {
            if (BoringInterop.SSL_CTX_set1_sigalgs_list(_ctx, config.SigAlgs) != 1)
                throw new BoringSslException($"SSL_CTX_set1_sigalgs_list 失败: {BoringInterop.GetLastError()}");
        }

        // ★ Supported groups (curves)
        if (!string.IsNullOrEmpty(config.Curves))
        {
            if (BoringInterop.SSL_CTX_set1_curves_list(_ctx, config.Curves) != 1)
                throw new BoringSslException($"SSL_CTX_set1_curves_list 失败: {BoringInterop.GetLastError()}");
        }

        // ★ GREASE（CTX 级别）
        BoringInterop.SSL_CTX_set_grease_enabled(_ctx, config.GreaseEnabled ? 1 : 0);

        // ★ Extension 顺序（CTX 级别）
        BoringInterop.SSL_CTX_set_permute_extensions(_ctx, config.PermuteExtensions ? 1 : 0);

        // ★ 证书压缩（CTX 级别 — Chrome 使用 Brotli）
        foreach (var algId in config.CertCompressionAlgIds)
            BoringInterop.SSL_CTX_add_cert_compression_alg(_ctx, algId, 0, 0);

        // ★ 证书验证
        if (config.SkipCertVerification)
            BoringInterop.SSL_CTX_set_verify(_ctx, BoringInterop.SSL_VERIFY_NONE, 0);

        // 创建 SSL 对象
        _ssl = BoringInterop.SSL_new(_ctx);
        if (_ssl == 0) throw new BoringSslException("SSL_new 失败");

        // SNI
        BoringInterop.SSL_set_tlsext_host_name(_ssl, host);

        // ★ ECH GREASE（SSL 级别）
        if (config.EchGreaseEnabled)
            BoringInterop.SSL_set_enable_ech_grease(_ssl, 1);

        // ★ SCT（SSL 级别）
        if (config.SctEnabled)
            BoringInterop.SSL_enable_signed_cert_timestamps(_ssl);

        // ★ OCSP Stapling（SSL 级别）
        if (config.OcspStaplingEnabled)
            BoringInterop.SSL_enable_ocsp_stapling(_ssl);

        // ALPN
        if (config.AlpnProtos is { Length: > 0 })
        {
            var alpnBytes = BoringInterop.BuildAlpnProtos(config.AlpnProtos);
            ref var alpnRef = ref alpnBytes[0];
            BoringInterop.SSL_set_alpn_protos(_ssl, ref alpnRef, alpnBytes.Length);
        }

        // ★ ALPS（SSL 级别 — 在 ALPN 之后设置）
        foreach (var alpsProto in config.AlpsProtocols)
        {
            var protoBytes = System.Text.Encoding.ASCII.GetBytes(alpsProto);
            var emptySettings = Array.Empty<byte>();
            ref var protoRef = ref protoBytes[0];
            // 空 settings — 只是声明支持 ALPS
            if (emptySettings.Length == 0)
            {
                byte dummy = 0;
                BoringInterop.SSL_add_application_settings(
                    _ssl, ref protoRef, (nuint)protoBytes.Length, ref dummy, 0);
            }
        }

        // 客户端模式
        BoringInterop.SSL_set_connect_state(_ssl);

        // memory BIO（与 TCP 解耦）
        _rbio = BoringInterop.BIO_new(BoringInterop.BIO_s_mem());
        _wbio = BoringInterop.BIO_new(BoringInterop.BIO_s_mem());
        if (_rbio == 0 || _wbio == 0) throw new BoringSslException("BIO_new 失败");

        // SSL_set_bio 接管 BIO 所有权
        BoringInterop.SSL_set_bio(_ssl, _rbio, _wbio);
    }

    /// <summary>握手后协商的 ALPN 协议（如 "h2" 或 "http/1.1"）</summary>
    public string? NegotiatedProtocol { get; private set; }

    /// <summary>执行 TLS 握手 — 通过 BIO memory 循环驱动</summary>
    public async Task AuthenticateAsync(CancellationToken ct = default)
    {
        while (true)
        {
            var ret = BoringInterop.SSL_do_handshake(_ssl);
            if (ret == 1)
            {
                await FlushWBioAsync(ct);
                _authenticated = true;

                // 查询协商的 ALPN
                BoringInterop.SSL_get0_alpn_selected(_ssl, out var alpnData, out var alpnLen);
                if (alpnData != 0 && alpnLen > 0)
                    NegotiatedProtocol = Marshal.PtrToStringAnsi(alpnData, alpnLen);

                return;
            }

            var error = BoringInterop.SSL_get_error(_ssl, ret);
            switch (error)
            {
                case BoringInterop.SSL_ERROR_WANT_WRITE:
                    await FlushWBioAsync(ct);
                    break;

                case BoringInterop.SSL_ERROR_WANT_READ:
                    await FlushWBioAsync(ct);
                    await FeedRBioAsync(ct);
                    break;

                default:
                    throw new BoringSslException($"SSL_do_handshake 失败 (error={error}): {BoringInterop.GetLastError()}");
            }
        }
    }

    // ============ Stream 读写 ============

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        EnsureAuthenticated();

        while (true)
        {
            ref var bufRef = ref buffer[offset];
            var ret = BoringInterop.SSL_read(_ssl, ref bufRef, count);
            if (ret > 0) return ret;

            var error = BoringInterop.SSL_get_error(_ssl, ret);
            switch (error)
            {
                case BoringInterop.SSL_ERROR_ZERO_RETURN:
                    return 0;
                case BoringInterop.SSL_ERROR_WANT_READ:
                    await FeedRBioAsync(ct);
                    break;
                case BoringInterop.SSL_ERROR_WANT_WRITE:
                    await FlushWBioAsync(ct);
                    break;
                default:
                    throw new BoringSslException($"SSL_read 失败 (error={error}): {BoringInterop.GetLastError()}");
            }
        }
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        // Memory<byte> → 临时 byte[] 桥接（避免 pin 复杂性）
        var temp = new byte[buffer.Length];
        var read = await ReadAsync(temp, 0, temp.Length, ct);
        if (read > 0)
            temp.AsMemory(0, read).CopyTo(buffer);
        return read;
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        EnsureAuthenticated();

        ref var bufRef = ref buffer[offset];
        var ret = BoringInterop.SSL_write(_ssl, ref bufRef, count);
        if (ret <= 0)
        {
            var error = BoringInterop.SSL_get_error(_ssl, ret);
            throw new BoringSslException($"SSL_write 失败 (error={error}): {BoringInterop.GetLastError()}");
        }

        await FlushWBioAsync(ct);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        var temp = buffer.ToArray();
        await WriteAsync(temp, 0, temp.Length, ct);
    }

    // ============ BIO 数据搬运 ============

    private async Task FlushWBioAsync(CancellationToken ct)
    {
        while (true)
        {
            var pending = (int)BoringInterop.BIO_ctrl_pending(_wbio);
            if (pending <= 0) break;

            var toRead = Math.Min(pending, _ioBuf.Length);
            ref var bufRef = ref _ioBuf[0];
            var read = BoringInterop.BIO_read(_wbio, ref bufRef, toRead);
            if (read > 0)
                await _inner.WriteAsync(_ioBuf.AsMemory(0, read), ct);
        }
        await _inner.FlushAsync(ct);
    }

    private async Task FeedRBioAsync(CancellationToken ct)
    {
        var read = await _inner.ReadAsync(_ioBuf, ct);
        if (read <= 0) throw new IOException("TCP 连接已关闭");

        ref var bufRef = ref _ioBuf[0];
        var written = BoringInterop.BIO_write(_rbio, ref bufRef, read);
        if (written != read)
            throw new BoringSslException($"BIO_write 只写入了 {written}/{read} 字节");
    }

    private void EnsureAuthenticated()
    {
        if (!_authenticated)
            throw new InvalidOperationException("尚未完成 TLS 握手，请先调用 AuthenticateAsync");
    }

    // ============ Stream 抽象实现 ============

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush() => _inner.Flush();

    protected override void Dispose(bool disposing)
    {
        if (_disposed) return;
        _disposed = true;

        if (_ssl != 0) { BoringInterop.SSL_free(_ssl); _ssl = 0; }
        // SSL_free 自动释放关联的 BIO
        if (_ctx != 0) { BoringInterop.SSL_CTX_free(_ctx); _ctx = 0; }

        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}
