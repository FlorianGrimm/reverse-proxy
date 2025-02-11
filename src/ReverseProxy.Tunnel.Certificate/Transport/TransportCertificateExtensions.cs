// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Utilities;

namespace Microsoft.AspNetCore.Builder;

public static class TransportCertificateExtensions
{
    /// <summary>
    /// Enable the ClientCertificate authentication tunnel transport on the backend.
    /// </summary>
    /// <remarks>
    /// Request/Response flow:
    /// <code>
    /// --------------------------------
    /// | Frontend                     |
    /// | AddTunnelServices            |
    /// | AddTunnelServicesCertificate |
    /// --------------------------------
    ///         ^     ||     /\
    ///         |     ||     ||
    ///         ^     \/     ||
    /// ---------------------------------
    /// | Backend                       |
    /// | AddTransportTunnel            |
    /// | AddTransportTunnelCertificate | ***
    /// ---------------------------------
    ///
    /// @Backend: Start the tunnel transport connections - the authentication is done via ClientCertificate
    /// @Frontend: Use the Yarp.ReverseProxy to forward the request to the Backend via the tunnel
    /// </code>
    ///
    /// <code>
    /// var reverseProxyBuilder = builder.Services.AddReverseProxy()
    ///     .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///     .AddTransportTunnel()
    ///     .AddReverseProxyCertificateManager(
    ///         configure: (options) =>
    ///         {
    ///             options.CertificateRootPath = System.AppContext.BaseDirectory;
    ///             options.CertificateRequirement = options.CertificateRequirement with
    ///             {
    ///                 AllowCertificateSelfSigned = true
    ///             };
    ///         }
    ///     )
    ///     .AddTransportTunnelCertificate()
    ///     ;
    /// </code>
    /// </remarks>
    /// <param name="builder">this</param>
    /// <param name="configuration">optional a configuration to load from</param>
    /// <param name="configure">optional a configure callback</param>
    /// <returns>fluent this</returns>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .AddTransportTunnel();
    ///
    ///    var app = builder.Build();
    ///
    ///    app.UseWhen(
    ///        static (context) => !context.IsTransportTunnelRequest(),
    ///        static (app) => app.UseHttpsRedirection()
    ///        );
    /// </example>
    public static IReverseProxyBuilder AddTransportTunnelCertificate(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = default,
        Action<TransportTunnelAuthenticationCertificateOptions>? configure = default
        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authenticator, TransportTunnelHttp2AuthenticatorCertificate>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthenticator, TransportTunnelWebSocketAuthenticatorCertificate>());

        {
            var optionsBuilder = services.AddOptions<TransportTunnelAuthenticationCertificateOptions>();
            if (configuration is { } || configure is { })
            {
                optionsBuilder.Configure((options) =>
                {
                    if (configuration is { })
                    {
                        options.Bind(configuration);
                    }
                    if (configure is { })
                    {
                        configure(options);
                    }
                });
            }
        }

        return builder;
    }

    public static IReverseProxyBuilder ConfigureCertificateManagerOptions
        (
            this IReverseProxyBuilder builder,
            IConfiguration? configuration = default,
            Action<CertificateManagerOptions>? configure = default
        )
    {
        var optionsBuilder = builder.Services.AddOptions<CertificateManagerOptions>();
        if (configuration is { } || configure is { })
        {
            _ = optionsBuilder.Configure((options) =>
            {
                if (configuration is { })
                {
                    options.Bind(configuration);
                }
                if (configure is { })
                {
                    configure(options);
                }
            });
        }


        return builder;
    }

    public static bool IsClientCertificate(string? mode)
        => string.Equals(
            mode,
            Yarp.ReverseProxy.Tunnel.TunnelCertificateConstants.AuthenticationMode,
            System.StringComparison.OrdinalIgnoreCase);

    public static void Bind(
        this TransportTunnelAuthenticationCertificateOptions that,
        IConfiguration configuration
        )
    {
        if (System.Enum.TryParse<SslProtocols>(configuration.GetSection(nameof(TransportTunnelAuthenticationCertificateOptions.EnabledSslProtocols)).Value, out var valueSslProtocols))
        {
            that.EnabledSslProtocols = valueSslProtocols;
        }
    }
}
