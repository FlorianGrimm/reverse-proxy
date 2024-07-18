using System;

namespace Yarp.ReverseProxy.Configuration;

public sealed record TransportTunnelConfig
{
    public string TunnelId { get; init; } = default!;
    public string Url { get; init; } = default!;
    public string RemoteTunnelId { get; init; } = default!;
    public TransportMode Transport { get; init; } = default!;
    public TransportTunnelAuthenticationConfig Authentication { get; init; } = new TransportTunnelAuthenticationConfig();

    public bool IsTunnelTransport => Transport == TransportMode.TunnelHTTP2 || Transport == TransportMode.TunnelWebSocket;
    public string GetRemoteTunnelId() => RemoteTunnelId is { Length: > 0 } value ? value : TunnelId;

    public bool Equals(TransportTunnelConfig? other)
    {
        if (other is null)
        {
            return false;
        }
        return
            string.Equals(TunnelId, other.TunnelId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Url, other.Url, StringComparison.OrdinalIgnoreCase)
            && string.Equals(RemoteTunnelId, other.RemoteTunnelId, StringComparison.OrdinalIgnoreCase)
            && Transport == other.Transport
            && Authentication == other.Authentication
            ;
    }
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(TunnelId?.GetHashCode(StringComparison.OrdinalIgnoreCase));
        hash.Add(Url?.GetHashCode(StringComparison.OrdinalIgnoreCase));
        hash.Add(RemoteTunnelId?.GetHashCode(StringComparison.OrdinalIgnoreCase));
        hash.Add(Transport);
        hash.Add(Authentication);
        return hash.ToHashCode();
    }
}
