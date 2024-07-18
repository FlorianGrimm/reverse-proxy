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
    public static IServiceCollection AddTunnelServices(this IServiceCollection services)
    {
        services.TryAddSingleton<TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, TunnelConnectionChannelManager.ClusterChangeListener>());

        services.TryAddSingleton<TunnelHTTP2Route>();
        services.TryAddSingleton<TunnelWebSocketRoute>();

        services.TryAddSingleton<TransportHttpClientFactorySelector>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelHTTP2HttpClientFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelWebSocketHttpClientFactory>());

        services.TryAddSingleton<TunnelAuthenticationService>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationAnonymous>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationCertificate>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationWindows>());

        services.TryAddSingleton<CertificatePathWatcher>();
        services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();

        _ = services.Configure<KestrelServerOptions>(kestrelServerOptions =>
        {
            var tunnelAuthenticationConfigService = kestrelServerOptions.ApplicationServices.GetRequiredService<TunnelAuthenticationService>();
            tunnelAuthenticationConfigService.ConfigureKestrelServer(kestrelServerOptions);
        });

        services.AddOptions<CertificateConfigOptions>()
            .PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));

        services.AddSingleton<ITunnelAuthenticationCookieService>(TunnelAuthenticationCookieService.Create);
         

        services.AddAuthorization(
            options => {
                TunnelAuthenticationWindows.ConfigureAuthorizationPolicy(options);
            });

        return services;
    }

    /// <summary>
    /// Enables tunnels (listener - on the front end) configured
    /// in the <see cref="Yarp.ReverseProxy.Configuration.ClusterConfig"/> Transport (e.g. TunnelHTTP2)
    /// </summary>
    /// <param name="builder">this builder</param>
    /// <returns>fluent this</returns>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .AddTunnelServices();
    /// </example>
    public static IReverseProxyBuilder AddTunnelServices(this IReverseProxyBuilder builder)
    {
        _ = builder.Services.AddTunnelServices();
        return builder;
    }

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
