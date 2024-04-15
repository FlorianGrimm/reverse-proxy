using System;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Model;

public class TunnelBackendToFrontendState
    : IEquatable<TunnelBackendToFrontendState>
{
    public string TunnelId { get; init; } = default!;
    public string Transport { get; init; } = default!;

    public string RemoteTunnelId { get; init; } = default!;

    public int MaxConnectionCount { get; init; } = 10;

    public string Url { get; init; } = default!;


    public TunnelBackendToFrontendAuthenticationConfig Authentication { get; init; } = default!;

    public override bool Equals(object? obj)
    {
        return (obj is TunnelBackendToFrontendState other) && Equals(other);
    }

    public bool Equals(TunnelBackendToFrontendState? other)
    {
        return TunnelId == other?.TunnelId
            && Transport == other.Transport
            // TODO: later && Authentication.Equals(other.Authentication)
            ;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            TunnelId,
            Transport
            // TODO: later Authentication
            );
    }
}
