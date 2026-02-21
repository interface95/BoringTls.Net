namespace BoringTls.Net;

/// <summary>BoringSSL 操作异常</summary>
public sealed class BoringSslException(string message) : Exception(message);
