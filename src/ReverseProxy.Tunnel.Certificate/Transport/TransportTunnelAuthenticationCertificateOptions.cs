// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelAuthenticationCertificateOptions
{
    /// <summary>
    /// Gets or sets the certificate revocation mode for certificate validation.
    /// </summary>
    public X509RevocationMode? CertificateRevocationCheckMode { get; set; }

    /// <summary>
    /// Gets or sets the SSL protocols that are enabled for SSL/TLS connections.
    /// </summary>
    public SslProtocols? EnabledSslProtocols { get; set; }

    public Action<SslClientAuthenticationOptions>? ConfigureSslOptions { get; set; }

    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; } = SslPolicyErrors.None;

    public Func<X509Certificate, X509Chain?, SslPolicyErrors, bool, bool>? CustomValidation { get; set; }

    public Action<ClientWebSocketOptions>? ConfigureClientWebSocketOptions { get; set; }
}
