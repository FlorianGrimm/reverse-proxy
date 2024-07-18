// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

namespace Yarp.ReverseProxy.Configuration;

public sealed record ClusterTunnelAuthenticationConfig
{
    public string? Mode { get; init; }

    public CertificateConfig? ClientCertificate { get; init; }

    public string[]? UserNames { get; init; }

    public bool Equals(ClusterTunnelAuthenticationConfig? other)
    {
        if (other is null)
        {
            return false;
        }

        if (!string.Equals(Mode, other.Mode, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (ClientCertificate is null && other.ClientCertificate is null)
        {
            return true;
        }
        if (ClientCertificate is null || other.ClientCertificate is null)
        {
            return false;
        }
        return ClientCertificate.Equals(other.ClientCertificate);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            Mode?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            ClientCertificate);
    }
}
