// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelOptions
{
    /// <summary>
    /// Enables or disables the anonymous tunnel authentication.
    /// This is really not recommended for production use.
    /// Please do use it - only for testing/trouble shooting purposes.
    /// This allows anyone to answer the request instead of your servers.
    /// You have been warned - DONT USE IT.
    /// </summary>
    public bool TunnelAuthenticationAnonymous { get; set; } = false;

    /// <summary>
    /// Enables or disables the client certificate tunnel authentication.
    /// A client certificate is required for the tunnel.
    /// You have to configure the authentication, e.g.
    /// <code>
    ///    builder.Services.AddAuthentication()
    ///        .AddCertificate(options =>
    ///        {
    ///            options.AllowedCertificateTypes = CertificateTypes.Chained;
    ///            options.RevocationMode = ....;
    ///        });
    /// </code>
    /// </summary>
    public bool TunnelAuthenticationCertificate { get; set; } = true;

    /// <summary>
    /// Enables or disables the Windows authentication for the tunnel.
    /// A Windows account is required for the tunnel.
    /// This might be useful for a corporate environment with firewall or inner VPNs.
    /// You have to configure the authentication, e.g.
    /// <code>
    ///     builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    ///         .AddNegotiate();
    /// </code>
    /// </summary>
    public bool TunnelAuthenticationWindows { get; set; } = true;
}
