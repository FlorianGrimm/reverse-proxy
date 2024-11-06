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
    /// <param name="configure"></param>
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
        Action<TransportTunnelAuthenticationCertificateOptions>? configure = default
        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authenticator, TransportTunnelHttp2AuthenticatorCertificate>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthenticator, TransportTunnelWebSocketAuthenticatorCertificate>());

        if (!services.Any(sd => typeof(ICertificateManager).Equals(sd.ServiceType))) {
            services.AddReverseProxyCertificateManager();
        }

        {
            var optionsBuilder = services.AddOptions<TransportTunnelAuthenticationCertificateOptions>();
            if (configure is { })
            {
                optionsBuilder.Configure(configure);
            }
        }

        // RemoteCertificateValidationUtility
        {
            services.AddSingleton<RemoteCertificateValidationUtility>();
            var optionsBuilder = services.AddOptions<RemoteCertificateValidationOptions>();
            optionsBuilder.PostConfigure<IOptions<TransportTunnelAuthenticationCertificateOptions>>(
                (options, ttacOptions) =>
                {
                    var ttacOptionsValue = ttacOptions.Value;
                    if (ttacOptionsValue.IgnoreSslPolicyErrors != System.Net.Security.SslPolicyErrors.None)
                    {
                        options.IgnoreSslPolicyErrors = ttacOptionsValue.IgnoreSslPolicyErrors;
                    }
                    if (ttacOptionsValue.CustomValidation is { })
                    {
                        options.CustomValidation = ttacOptionsValue.CustomValidation;
                    }
                });
        }

        return builder;
    }

    public static IReverseProxyBuilder ConfigureCertificateManagerOptions
        (
            this IReverseProxyBuilder builder,
            Action<CertificateManagerOptions>? configure = default,
            IConfiguration? configuration = default
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
