// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Configuration;

/// <summary>
/// Describes the authentication configuration for a transport tunnel.
/// </summary>
public sealed record TransportTunnelAuthenticationConfig
{
    /// <summary>
    /// The authentication mode. e.g. "Certificate".
    /// </summary>
    public string? Mode { get; init; }

    /// <summary>
    /// The client certificate.
    /// </summary>
    public string? ClientCertificate { get; init; }

    /// <summary>
    /// Arbitrary key-value pairs that further describe this authentication.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Metadata { get; init; }


    /// <inheritdoc/>
    public bool Equals(TransportTunnelAuthenticationConfig? other)
    {
        if (other is null) { return false; }
        if (ReferenceEquals(this, other)) { return true; }
        return (string.Equals(Mode, other.Mode, StringComparison.OrdinalIgnoreCase))
            && (string.Equals(ClientCertificate, other.ClientCertificate, StringComparison.OrdinalIgnoreCase))
            && CaseSensitiveEqualHelper.Equals(Metadata, other.Metadata);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hashCode = new HashCode();
        hashCode.Add(Mode, StringComparer.OrdinalIgnoreCase);
        hashCode.Add(ClientCertificate, StringComparer.OrdinalIgnoreCase);
        hashCode.Add(CaseSensitiveEqualHelper.GetHashCode(Metadata));
        return hashCode.ToHashCode();
    }
}
