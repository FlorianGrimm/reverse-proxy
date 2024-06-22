// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Configuration;

public record TunnelAuthenticationConfig
{
    // TODO: specify X509Certificate: borrow form kestrel??

    // for in-memory configuration
    public X509CertificateCollection? ClientCertifiacteCollection { get; init; }
}
