using System;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Configuration;

/// <summary>
/// Represents the configuration for a transport tunnel.
/// </summary>
public sealed record TransportTunnelConfig {
    /// <summary>
    /// Gets or initializes the tunnel identifier.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    /// <summary>
    /// Gets or initializes the URL of the transport tunnel.
    /// </summary>
    public string Url { get; init; } = default!;

    /// <summary>
    /// Gets or initializes the remote tunnel identifier.
    /// </summary>
    public string RemoteTunnelId { get; init; } = default!;

    /// <summary>
    /// Gets or initializes the transport type.
    /// </summary>
    public string Transport { get; init; } = default!;

    /// <summary>
    /// Gets or initializes the authentication configuration for the transport tunnel.
    /// </summary>
    public TransportTunnelAuthenticationConfig Authentication { get; init; } = new TransportTunnelAuthenticationConfig();

    /// <summary>
    /// Gets a value indicating whether the transport is a tunnel transport.
    /// </summary>
    public bool IsTunnelTransport => string.IsNullOrEmpty(Transport) ? false : Transport.StartsWith("Tunnel");

    /// <summary>
    /// Gets the remote tunnel identifier, or the tunnel identifier if the remote tunnel identifier is not set.
    /// </summary>
    /// <returns>The remote tunnel identifier or the tunnel identifier.</returns>
    public string GetRemoteTunnelId() => RemoteTunnelId is { Length: > 0 } value ? value : TunnelId;

    /// <summary>
    /// Determines whether the specified <see cref="TransportTunnelConfig"/> is equal to the current <see cref="TransportTunnelConfig"/>.
    /// </summary>
    /// <param name="other">The <see cref="TransportTunnelConfig"/> to compare with the current <see cref="TransportTunnelConfig"/>.</param>
    /// <returns>true if the specified <see cref="TransportTunnelConfig"/> is equal to the current <see cref="TransportTunnelConfig"/>; otherwise, false.</returns>
    public bool Equals(TransportTunnelConfig? other) {
        if (other is null) {
            return false;
        }
        return
            string.Equals(TunnelId, other.TunnelId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Url, other.Url, StringComparison.OrdinalIgnoreCase)
            && string.Equals(RemoteTunnelId, other.RemoteTunnelId, StringComparison.OrdinalIgnoreCase)
            && Transport == other.Transport
            && Authentication == other.Authentication;
    }

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode() {
        var hash = new HashCode();
        hash.Add(TunnelId?.GetHashCode(StringComparison.OrdinalIgnoreCase));
        hash.Add(Url?.GetHashCode(StringComparison.OrdinalIgnoreCase));
        hash.Add(RemoteTunnelId?.GetHashCode(StringComparison.OrdinalIgnoreCase));
        hash.Add(Transport);
        hash.Add(Authentication);
        return hash.ToHashCode();
    }
}
