// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Configuration;

public sealed record ClusterTunnelAuthenticationConfig
{
    public string? Mode { get; init; }

    public List<CertificateConfig> ClientCertificates { get; init; } = [];

    public CertificateConfig? ClientCertificate { get; init; }

    /// <summary>
    /// for in-memory configuration
    /// </summary>
    public X509Certificate2Collection? ClientCertificateCollection { get; init; }

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

        {
            if (ClientCertificate is null && other.ClientCertificate is null)
            {
                // OK
            }
            if (ClientCertificate is null || other.ClientCertificate is null)
            {
                return false;
            }
            if (!ClientCertificate.Equals(other.ClientCertificate))
            {
                return false;
            }
        }

        {
            if (ClientCertificates.Count != other.ClientCertificates.Count)
            {
                return false;
            }
            for (var index = 0; index < ClientCertificates.Count; index++)
            {
                if (!ClientCertificates[index].Equals(other.ClientCertificates[index]))
                {
                    return false;
                }
            }
        }

        {
            if (ClientCertificateCollection is null && other.ClientCertificateCollection is null)
            {
            }

            if (ClientCertificateCollection is null || other.ClientCertificateCollection is null)
            {
                return false;
            }

            for (var index = 0; index < ClientCertificates.Count; index++)
            {
                if (!ClientCertificateCollection[index].Equals(other.ClientCertificateCollection[index]))
                {
                    return false;
                }
            }
        }

        return true;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            Mode?.GetHashCode(StringComparison.OrdinalIgnoreCase),
            ClientCertificate);
    }
}
