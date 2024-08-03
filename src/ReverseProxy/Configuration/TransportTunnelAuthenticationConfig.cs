// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Configuration;

public sealed record TransportTunnelAuthenticationConfig
{
    public string? Mode { get; init; }

    public List<CertificateConfig> ClientCertificates { get; init; } = [];

    public CertificateConfig? ClientCertificate { get; init; }

    /// <summary>
    /// for in-memory configuration
    /// </summary>
    public X509CertificateCollection? ClientCertificateCollection { get; init; }

    /// <inheritdoc/>
    public bool Equals(TransportTunnelAuthenticationConfig? other)
    {
        if (other is null)
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

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var certificateConfig in ClientCertificates)
        {
            hash.Add(certificateConfig);
        }
        if (ClientCertificate is { })
        {
            hash.Add(ClientCertificate);
        }
        if (ClientCertificateCollection is { })
        {
            foreach (var certificate in ClientCertificateCollection)
            {
                hash.Add(certificate.GetSerialNumber());
            }
        }
        return hash.ToHashCode();
    }
}
