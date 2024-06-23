// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Configuration;

public sealed record TransportAuthenticationConfig
{
    public string? Mode { get; init; }

    public CertificateConfig? ClientCertificate { get; init; }
}
