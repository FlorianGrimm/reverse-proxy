// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelExtensions
{
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
    /// | AddTunnelServices            | &lt;- this
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
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .AddTunnelServices();
    ///        
    ///    app.UseWhen(
    ///        static context => !context.TryGetTransportTunnelByUrl(out var _),
    ///        app => app.UseHttpsRedirection()
    ///        );
    /// </example>
    public static IReverseProxyBuilder AddTunnelServices(
        this IReverseProxyBuilder builder,
        TunnelServicesOptions? options = default
        )
    {
        var services = builder.Services;

        services.TryAddNoOpCertificateManager();
        services.TryAddSingleton<TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, TunnelConnectionChannelManager.ClusterChangeListener>());
        services.TryAddSingleton<TransportForwarderHttpClientFactorySelector>();

        if (options is null || options.TunnelHTTP2)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelRouteService, TunnelHTTP2Route>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportForwarderHttpClientFactorySelector, TunnelHTTP2HttpClientFactory>());
        }
        if (options is null || options.TunnelWebSocket)
        {
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelRouteService, TunnelWebSocketRoute>());
            services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportForwarderHttpClientFactorySelector, TunnelWebSocketHttpClientFactory>());
        }
        if (options is not null && !options.TunnelHTTP2 && !options.TunnelWebSocket)
        {
            throw new NotSupportedException("At least one of the TunnelHTTP2 or TunnelWebSocket must be enabled.");
        }

        services.TryAddSingleton<ITunnelAuthenticationConfigService, TunnelAuthenticationConfigService>();

        _ = services.Configure<KestrelServerOptions>(kestrelServerOptions =>
        {
            var tunnelAuthenticationConfigService = kestrelServerOptions.ApplicationServices.GetRequiredService<ITunnelAuthenticationConfigService>();
            (tunnelAuthenticationConfigService as TunnelAuthenticationConfigService)?.ConfigureKestrelServer(kestrelServerOptions);
        });

        services.AddSingleton<ITunnelAuthenticationCookieService>(TunnelAuthenticationCookieService.Create);

        return builder;
    }

    // add the tunnel endpoint routes
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    internal static void MapTunnels(
        this IEndpointRouteBuilder endpoints,
        Dictionary<string, Action<IEndpointConventionBuilder>>? configureEndpoints = default)
    {
        var tunnelRouteServices = endpoints.ServiceProvider.GetServices<ITunnelRouteService>();
        foreach (var tunnelRouteService in tunnelRouteServices)
        {
            var transport = tunnelRouteService.GetTransport();
            if (configureEndpoints is not null && configureEndpoints.TryGetValue(transport, out var configureAction))
            {
                tunnelRouteService.Map(endpoints, configureAction);
            }
            else
            {
                tunnelRouteService.Map(endpoints, null);
            }
        }
    }
}
