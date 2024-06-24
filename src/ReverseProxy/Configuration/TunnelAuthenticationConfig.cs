// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Mvc;

namespace Yarp.ReverseProxy.Configuration;

public sealed record TunnelAuthenticationConfig
{
    public string? Mode { get; init; }

    // TODO
    public List<CertificateConfig> ClientCertificates { get; init; } = new List<CertificateConfig>();

    // TODO: specify X509Certificate: borrow form kestrel??

    // for in-memory configuration
    public X509CertificateCollection? ClientCertifiacteCollection { get; init; }

    public bool Equals(TunnelAuthenticationConfig? other)
    {
        if (other is null)
        {
            return false;
        }

        {
            if (ClientCertificates.Count != other.ClientCertificates.Count)
            {
                return false;
            }
            for (var i = 0; i < ClientCertificates.Count; i++)
            {
                if (!ClientCertificates[i].Equals(other.ClientCertificates[i]))
                {
                    return false;
                }
            }
        }

        {
            if (ClientCertifiacteCollection is null && other.ClientCertifiacteCollection is null)
            {
                return true;
            }

            if (ClientCertifiacteCollection is null || other.ClientCertifiacteCollection is null)
            {
                return false;
            }

            if (ClientCertifiacteCollection != other.ClientCertifiacteCollection)
            {
                return false;
            }
        }

        return true;
    }
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(ClientCertificates.Count);
        for (var i = 0; i < ClientCertificates.Count; i++)
        {
            hash.Add(ClientCertificates[i]);
        }
        return hash.ToHashCode();
    }

}
