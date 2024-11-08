// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Options for configuring certificate-based authentication for transport tunnels.
/// </summary>
public sealed class TransportTunnelAuthenticationCertificateOptions {
    /// <summary>
    /// Gets or sets the certificate revocation mode for certificate validation.
    /// </summary>
    public X509RevocationMode? CertificateRevocationCheckMode { get; set; }

    /// <summary>
    /// Gets or sets the SSL protocols that are enabled for SSL/TLS connections.
    /// </summary>
    public SslProtocols? EnabledSslProtocols { get; set; }

    /// <summary>
    /// Gets or sets an action to configure SSL client authentication options.
    /// </summary>
    public Action<SslClientAuthenticationOptions>? ConfigureSslOptions { get; set; }

    /// <summary>
    /// Gets or sets the SSL policy errors to ignore during certificate validation.
    /// </summary>
    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; } = SslPolicyErrors.None;

    /// <summary>
    /// Gets or sets a custom validation function for certificates.
    /// </summary>
    /// <remarks>
    /// The function takes the certificate, the certificate chain, the SSL policy errors, and a boolean indicating whether the validation is for a server.
    /// It returns a boolean indicating whether the certificate is valid.
    /// </remarks>
    public Func<X509Certificate, X509Chain?, SslPolicyErrors, bool, bool>? CustomValidation { get; set; }

    /// <summary>
    /// Gets or sets an action to configure client WebSocket options.
    /// </summary>
    public Action<ClientWebSocketOptions>? ConfigureClientWebSocketOptions { get; set; }

    /// <summary>
    /// Gets or sets the certificate requirement for the tunnel.
    /// </summary>
    public CertificateRequirement CertificateRequirement { get; set; } = new();
}
