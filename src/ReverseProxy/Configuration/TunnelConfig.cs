// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Configuration;

/// <summary>
/// Tunnels configuration.
/// </summary>
public sealed record TunnelConfig
{
    /// <summary>
    /// The Id for this tunnel. This needs to be globally unique.
    /// This field is required.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    public string Url { get; init; } = default!;

    public string ListenUrl { get; init; } = default!;

    public TunnelTransportType Transport { get; init; } = TunnelTransportType.HTTP2;

    public int MaxConnectionCount { get; set; } = 10;

    // TODO: public AuthenticationConfig Authentication { get; init; } = default!;

    public string GetUrl() {
        if (string.IsNullOrEmpty(Url)) { return string.Empty; }
        return $"{Url}/Tunnel/{Transport}/{TunnelId}";
    }

    /// <summary>
    /// Arbitrary key-value pairs that further describe this tunnel.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }

    public bool Equals(TunnelConfig? other)
    {
        if (other is null)
        {
            return false;
        }

        return string.Equals(TunnelId, other.TunnelId, StringComparison.OrdinalIgnoreCase)
            && string.Equals(ListenUrl, other.ListenUrl, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Url, other.Url, StringComparison.OrdinalIgnoreCase)
            && Transport == other.Transport
            && CaseSensitiveEqualHelper.Equals(Metadata, other.Metadata);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            TunnelId?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            ListenUrl?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            Url?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            Transport,
            CaseSensitiveEqualHelper.GetHashCode(Metadata));
    }
}

