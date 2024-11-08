// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

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
    public CertificateConfig? ClientCertificate { get; init; }

    /// <summary>
    /// A list of client certificates.
    /// </summary>
    public List<CertificateConfig> ClientCertificates { get; init; } = [];

    /// <summary>
    /// for in-memory configuration
    /// </summary>
    public X509Certificate2Collection? ClientCertificateCollection { get; init; }

    /// <summary>
    /// The certificate requirement.
    /// </summary>
    public CertificateRequirement CertificateRequirement { get; init; } = new CertificateRequirement();

    /// <inheritdoc/>
    public bool Equals(TransportTunnelAuthenticationConfig? other)
    {
        if (other is null) { return false; }
        if (ReferenceEquals(this, other)) { return true; }
        return (string.Equals(Mode, other.Mode, StringComparison.Ordinal))
            && (CertificateConfigUtility.EqualCertificateConfigQ(ClientCertificate, other.ClientCertificate))
            && (CertificateConfigUtility.EqualCertificateConfigsQ(ClientCertificates, other.ClientCertificates))
            && (CertificateConfigUtility.EqualCertificateCollectionQ(ClientCertificateCollection, other.ClientCertificateCollection))
            && (CertificateRequirement.Equals(other.CertificateRequirement))
            ;
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
        hash.Add(CertificateRequirement);
        return hash.ToHashCode();
    }
}
