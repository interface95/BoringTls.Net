using System.Net;
using System.Net.Sockets;

namespace BoringTls.Net;

/// <summary>
/// BoringSSL HttpClient 工厂 — 创建带精确 TLS 指纹的 HttpClient
/// </summary>
public static class BoringHttpClientFactory
{
    /// <summary>
    /// 创建使用 BoringSSL 做 TLS 握手的 HttpClient — 精确控制 ClientHello 指纹
    /// </summary>
    public static HttpClient Create(BoringTlsConfig config)
        => new(new BoringSslDelegatingHandler(CreateSocketsHandler(config)));

    /// <summary>
    /// 返回 BoringSSL HttpMessageHandler（给 YARP HttpMessageInvoker 等场景用）
    /// </summary>
    public static HttpMessageHandler CreateHandler(BoringTlsConfig config)
        => new BoringSslDelegatingHandler(CreateSocketsHandler(config));

    private static SocketsHttpHandler CreateSocketsHandler(BoringTlsConfig config)
        => new()
        {
            Proxy = null,
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(5),
            MaxConnectionsPerServer = 10,
            EnableMultipleHttp2Connections = true,
            ConnectCallback = async (context, ct) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(context.DnsEndPoint, ct);
                var networkStream = new NetworkStream(socket, ownsSocket: true);

                var ssl = new BoringSslStream(networkStream, context.DnsEndPoint.Host, config);
                await ssl.AuthenticateAsync(ct);
                return ssl;
            },
        };
}

/// <summary>
/// Scheme 降级处理器 — 将 https:// 改为 http:// 骗过 SocketsHttpHandler 不加 SslStream。
/// TLS 已由 ConnectCallback 中的 BoringSslStream 处理。
/// </summary>
file sealed class BoringSslDelegatingHandler(SocketsHttpHandler inner) : DelegatingHandler(inner)
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken ct)
    {
        if (request.RequestUri?.Scheme == "https")
        {
            var builder = new UriBuilder(request.RequestUri)
            {
                Scheme = "http",
                Port = request.RequestUri.Port == -1 ? 443 : request.RequestUri.Port,
            };
            request.RequestUri = builder.Uri;
        }

        request.Version = System.Net.HttpVersion.Version20;
        request.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;

        return base.SendAsync(request, ct);
    }
}
