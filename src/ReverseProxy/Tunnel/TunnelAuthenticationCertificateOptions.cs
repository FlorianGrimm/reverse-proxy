// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

public sealed class TunnelAuthenticationCertificateOptions
{
    public const string SectionName = "TunnelAuthenticationCertificate";

    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; }

    public Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? IsCertificateValid { get; set; }

    public void Bind(IConfiguration configuration)
    {
        if (System.Enum.TryParse<SslPolicyErrors>(configuration[nameof(IgnoreSslPolicyErrors)], out var valueIgnoreSslPolicyErrors))
        {
            IgnoreSslPolicyErrors = valueIgnoreSslPolicyErrors;
        }
    }
}
