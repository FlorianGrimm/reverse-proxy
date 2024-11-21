// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Configuration;

/// <summary>
/// Cluster tunnel authentication configuration.
/// </summary>
public sealed record ClusterTunnelAuthenticationConfig
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
    /// Gets or sets the user names, that is allowed.
    /// </summary>
    public string[]? UserNames { get; init; }

    public bool Equals(ClusterTunnelAuthenticationConfig? other)
    {
        if (other is null) { return false; }
        if (ReferenceEquals(this, other)) { return true; }


        return string.Equals(Mode, other.Mode, StringComparison.OrdinalIgnoreCase)
            && string.Equals(ClientCertificate, other.ClientCertificate, StringComparison.Ordinal)
            && (UserNames ?? []).SequenceEqual(other.UserNames ?? [], StringComparer.OrdinalIgnoreCase);
        ;
    }

    public override int GetHashCode()
    {
        var result = new HashCode();
        result.Add(Mode, StringComparer.OrdinalIgnoreCase);
        result.Add(ClientCertificate);
        foreach (var item in UserNames ?? [])
        {
            result.Add(item, StringComparer.OrdinalIgnoreCase);
        }
        return result.ToHashCode();
    }
}
