// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Configuration;

public sealed record TransportAuthentication
{
    public List<CertificateConfig> ClientCertificates { get; init; } = new List<CertificateConfig>();
#warning HERE
    // TODO: specify X509Certificate: borrow form kestrel??

    // for in-memory configuration
    public X509CertificateCollection? ClientCertifiacteCollection { get; init; }
}
