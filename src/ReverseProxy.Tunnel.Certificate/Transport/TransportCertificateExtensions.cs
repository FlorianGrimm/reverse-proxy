// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

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
    /// | AddTunnelTransport            |
    /// | AddTunnelTransportCertificate | ***
    /// ---------------------------------
    ///
    /// @Backend: Start the tunnel transport connections - the authentication is done via ClientCertificate
    /// @Frontend: Use the Yarp.ReverseProxy to forward the request to the Backend via the tunnel
    /// </code>
    ///
    /// <code>
    /// var reverseProxyBuilder = builder.Services.AddReverseProxy()
    ///     .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///     .AddTunnelTransport()
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
    ///     .AddTunnelTransportCertificate()
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
    ///        .AddTunnelTransport();
    ///
    ///    var app = builder.Build();
    ///
    ///    app.UseWhen(
    ///        static context => !context.TryGetTransportTunnelByUrl(out var _),
    ///        app => app.UseHttpsRedirection()
    ///        );
    /// </example>
    public static IReverseProxyBuilder AddTunnelTransportCertificate(
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
                optionsBuilder.Configure((options) => {
                    if (configuration is { })
                    {
#warning TODO               options.Bind(configuration);
                    }
                    if (configure is { } ) {
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
        if (configuration is { })
        {
            _ = optionsBuilder.Configure((options) =>
            {
                options.Bind(configuration);
            });
        }

        if (configure is { })
        {
            _ = optionsBuilder.Configure(configure);
        }

        return builder;
    }

    public static bool IsClientCertificate(string? mode)
        => string.Equals(mode, "ClientCertificate", System.StringComparison.OrdinalIgnoreCase);
}
