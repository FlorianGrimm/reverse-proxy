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
    /// Enable the tunnel transport on the backend.
    /// For each tunnel-config connections are opened to URL/_tunnel/RemoteTunnelId or URL/_tunnel/TunnelId
    /// </summary>
    /// <remarks>
    /// Request/Response flow:
    /// <code>
    /// --------------------------------
    /// | Browser                      |
    /// --------------------------------
    ///             |(2)        ^
    ///             |           |
    ///             v           | (7)
    /// --------------------------------
    /// | Frontend                     |
    /// | AddTunnelServices            |
    /// --------------------------------
    ///         ^     ||(3)  /\
    ///         |     ||     ||
    ///         ^ (1) \/     || (6)
    /// --------------------------------
    /// | Backend                      |
    /// | AddTunnelTransport           |
    /// --------------------------------
    ///              (4) |  ^
    ///                  |  |
    ///                  v  | (5)
    /// --------------------------------
    /// | API                          |
    /// | ASP.Net Core Middleware      |
    /// --------------------------------
    ///
    /// 1) @Backend: Start the tunnel transport connections in a Kestrel IConnectionListener
    /// 2) @Browser: Request to the Frontend
    /// 3) @Frontend: Use the Yarp.ReverseProxy to forward the request to the Backend via the tunnel
    /// 4) @Backend: Use the Yarp.ReverseProxy to forward the request to the API
    /// 5) @API: Handle the request with the normal ASP.Net Core Middleware
    /// 6) @Backend: Use the tunnel connection response to send the response back to the Frontend.
    /// 7) @Frontend: Copy the response  the httpContext.Response
    /// </code>
    /// 3+6 the inner tunnel transport uses HTTP not HTTPS.
    /// The outer tunnel transport uses HTTPS - if you use it - and I hope so.
    /// Therefor the requests through the tunnel conflict with the UseHttpsRedirection.
    /// app.UseHttpsRedirection() will redirect if the request is a tunnel request;
    /// which means that the browser is redirected to https://{tunnelId}/... which is not what we want.
    /// <code>
    /// app.UseWhen(
    ///     static context => !context.TryGetTransportTunnelByUrl(out var _),
    ///     app => app.UseHttpsRedirection()
    ///     );
    /// </code>
    /// </remarks>
    /// <param name="builder">this</param>
    /// <param name="configure"> </param>
    /// <returns></returns>
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
