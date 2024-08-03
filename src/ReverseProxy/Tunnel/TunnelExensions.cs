// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelExensions
{
    /// <summary>
    /// Adds the services required for tunneling.
    /// </summary>
    /// <param name="services">this</param>
    /// <param name="options">options to </param>
    /// <returns>fluent this</returns>
    public static IServiceCollection AddTunnelServices(
        this IServiceCollection services,
        TunnelServicesOptions? options = default
        )
    {
        services.TryAddSingleton<TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, TunnelConnectionChannelManager.ClusterChangeListener>());
        services.TryAddSingleton<TransportForwarderHttpClientFactorySelector>();

        if (options is null || options.TunnelHTTP2)
        {
            services.TryAddSingleton<TunnelHTTP2Route>();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportForwarderHttpClientFactorySelector, TunnelHTTP2HttpClientFactory>());
        }
        if (options is null || options.TunnelWebSocket)
        {
            services.TryAddSingleton<TunnelWebSocketRoute>();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportForwarderHttpClientFactorySelector, TunnelWebSocketHttpClientFactory>());
        }
        if (options is not null && !options.TunnelHTTP2 && !options.TunnelWebSocket)
        {
            throw new NotSupportedException("At least one of the TunnelHTTP2 or TunnelWebSocket must be enabled.");
        }

        services.TryAddSingleton<TunnelAuthenticationService>();

        if (options is not null && options.TunnelAuthenticationAnonymous)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationAnonymous>());
        }

        if (options is null || options.TunnelAuthenticationCertificate)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationCertificate>());
            services.TryAddSingleton<CertificatePathWatcher>();
            services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();

            services.AddOptions<CertificateConfigOptions>()
                .PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));

        }

        if (options is null || options.TunnelAuthenticationWindows)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationWindows>());

            services.AddAuthorization(
                options =>
                {
                    TunnelAuthenticationWindows.ConfigureAuthorizationPolicy(options);
                });
        }

        _ = services.Configure<KestrelServerOptions>(kestrelServerOptions =>
        {
            var tunnelAuthenticationConfigService = kestrelServerOptions.ApplicationServices.GetRequiredService<TunnelAuthenticationService>();
            tunnelAuthenticationConfigService.ConfigureKestrelServer(kestrelServerOptions);
        });

        services.AddSingleton<ITunnelAuthenticationCookieService>(TunnelAuthenticationCookieService.Create);

        return services;
    }

    /// <summary>
    /// Enables tunnels (listener - on the front end) configured
    /// in the <see cref="Yarp.ReverseProxy.Configuration.ClusterConfig"/> Transport (e.g. TunnelHTTP2)
    /// </summary>
    /// <param name="builder">this builder</param>
    /// <param name="options">to enable/disable TunnelAuthentication</param>
    /// <returns>fluent this</returns>
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
    ///         |     ||(3)  /\
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
    /// 
    /// </remarks>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .AddTunnelServices();
    /// </example>
    public static IReverseProxyBuilder AddTunnelServices(
        this IReverseProxyBuilder builder,
        TunnelServicesOptions? options = default
        )
    {
        _ = builder.Services.AddTunnelServices(options);
        return builder;
    }

    // add the tunnel endpoint routes
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    internal static void MapTunnels(
        this IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configureTunnelHTTP2 = default,
        Action<IEndpointConventionBuilder>? configureTunnelWebSocket = default)
    {

        if (endpoints.ServiceProvider.GetService<TunnelHTTP2Route>() is { } tunnelHTTP2Route)
        {
            tunnelHTTP2Route.Map(endpoints, configureTunnelHTTP2);
        }

        if (endpoints.ServiceProvider.GetService<TunnelWebSocketRoute>() is { } tunnelWebSocketRoute)
        {
            tunnelWebSocketRoute.Map(endpoints, configureTunnelWebSocket);
        }
    }

    public static IReverseProxyBuilder ConfigureTunnelAuthenticationCertificateOptions(
        this IReverseProxyBuilder builder,
        Action<TunnelAuthenticationCertificateOptions>? configure = default,
        IConfiguration? configuration = default
        )
    {
        {
            var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationCertificateOptions>();
            if (configuration is { })
            {
                optionsBuilder.Configure((options) =>
                {
                    options.Bind(configuration.GetSection(TunnelAuthenticationCertificateOptions.SectionName));
                });
            }
            if (configure is { })
            {
                optionsBuilder.Configure(configure);
            }
        }

        return builder;
    }
}
