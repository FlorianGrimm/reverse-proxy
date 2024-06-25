using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;


public static class TunnelExensions
{
    public static IServiceCollection AddTunnelServices(this IServiceCollection services)
    {
        services.TryAddSingleton<TunnelAuthenticationConfigService>();
        services.TryAddSingleton<TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, TunnelConnectionChannelManager.ClusterChangeListener>());
        services.TryAddSingleton<TransportHttpClientFactorySelector>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelHTTP2HttpClientFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelWebSocketHttpClientFactory>());
        services.TryAddSingleton<TunnelHTTP2Route>();
        services.TryAddSingleton<TunnelWebSocketRoute>();
        services.TryAddSingleton<CertificatePathWatcher>();
        services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();
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
    public static IReverseProxyBuilder AddTunnelServices(
        this IReverseProxyBuilder builder)
    {
        builder.Services.AddTunnelServices();
        return builder;
    }

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
}
