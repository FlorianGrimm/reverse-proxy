using System;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Model;

/// <summary>
/// TODO
/// </summary>
public sealed class TunnelBackendToFrontendState
    : IEquatable<TunnelBackendToFrontendState>
{
    /// <summary>
    /// A unique identifier for the tunnel channel.
    /// </summary>
    public string TunnelChannelId { get; init; } = default!;

    /// <summary>
    /// TunnelId of the tunnel. Is the same as ChannelId.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    /// <summary>
    /// The transport used for the tunnel.
    /// </summary>
    public string Transport { get; init; } = default!;

    /// <summary>
    /// The TunnelId of the remote tunnel.
    /// </summary>
    public string RemoteTunnelId { get; init; } = default!;

    // TODO
    public int MaxConnectionCount { get; init; } = 10;

    /// <summary>
    /// The remote URL (protocol+server) to connect to.
    /// </summary>
    public string Url { get; init; } = default!;

    /// <summary>
    /// calculated TunnelId-TunnelChannelId-Hostname
    /// </summary>
    /// <remarks>
    /// Not part of equality comparison nor GetHash.
    /// </remarks>
    public string RemoteHost { get; init; } = default!;

    /// <summary>
    /// Big TODO
    /// </summary>
    public TunnelBackendToFrontendAuthenticationConfig Authentication { get; init; } = default!;

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return (obj is TunnelBackendToFrontendState other) && Equals(other);
    }

    /// <inheritdoc/>
    public bool Equals(TunnelBackendToFrontendState? other)
    {
        if (other == null)
        {
            return false;
        }
        else
        {
            return TunnelChannelId == other.TunnelChannelId
                && TunnelId == other.TunnelId
                && Transport == other.Transport
                // TODO: later && Authentication.Equals(other.Authentication)
                ;
        }
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(
            TunnelChannelId,
            TunnelId,
            Transport
            // TODO: later Authentication
            );
    }
}
