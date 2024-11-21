// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Utilities;

namespace Microsoft.AspNetCore.Builder;

public static class WebHostBuilderExtensions
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
    /// | AddTunnelTransport           | &lt- this
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
    /// <param name="configureTunnelHttp2">configure transport tunnel for Http2.</param>
    /// <param name="configureTunnelWebSocket">configure transport tunnel for WebSocket.</param>
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
    public static IReverseProxyBuilder AddTunnelTransport(
        this IReverseProxyBuilder builder,
        Action<TransportTunnelHttp2Options>? configureTunnelHttp2 = default,
        Action<TransportTunnelWebSocketOptions>? configureTunnelWebSocket = default
        )
    {

        var services = builder.Services
            .AddSingleton<ITunnelChangeListener, TransportTunnelConnectionChangeListener>()
            .AddSingleton<TransportTunnelFactory>()
            ;

        services.TryAdd(ServiceDescriptor.Transient<IncrementalDelay, IncrementalDelay>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelFactory, TransportTunnelHttp2Factory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelFactory, TransportTunnelWebSocketFactory>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelHttp2ConnectionListenerFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelWebSocketConnectionListenerFactory>());

        services.AddSingleton<TransportTunnelHttp2Authentication>();
        services.AddSingleton<TransportTunnelWebSocketAuthentication>();

        if (configureTunnelHttp2 is not null)
        {
            _ = services.Configure(configureTunnelHttp2);
        }

        if (configureTunnelWebSocket is not null)
        {
            _ = services.Configure(configureTunnelWebSocket);
        }

        _ = services.Configure<KestrelServerOptions>(ConfigureTransportTunnels);

        return builder;
    }

    private static void ConfigureTransportTunnels(KestrelServerOptions options)
    {
        var proxyConfigManager = options.ApplicationServices.GetRequiredService<ProxyConfigManager>();
        var tunnels = proxyConfigManager.GetTransportTunnels();

        var transportTunnelFactory = options.ApplicationServices.GetRequiredService<TransportTunnelFactory>();

        var transportTunnelHttp2Options = options.ApplicationServices.GetRequiredService<IOptions<TransportTunnelHttp2Options>>().Value;
        var transportTunnelWebSocketOptions = options.ApplicationServices.GetRequiredService<IOptions<TransportTunnelWebSocketOptions>>().Value;

        var listAuthenticationNameH2 = options.ApplicationServices.GetRequiredService<TransportTunnelHttp2Authentication>().GetAuthenticationNames();
        var listAuthenticationNameWS = options.ApplicationServices.GetRequiredService<TransportTunnelWebSocketAuthentication>().GetAuthenticationNames();

        foreach (var tunnel in tunnels)
        {
            var cfg = tunnel.Model.Config;
            var remoteTunnelId = cfg.GetRemoteTunnelId();
            var host = cfg.Url.TrimEnd('/');

            var transport = cfg.Transport;

            var cfgAuthenticationMode = cfg.Authentication.Mode;

            if (transportTunnelFactory.TryGetTransportTunnelFactory(cfg.Transport, out var factory))
            {
                factory.Listen(tunnel, options);
            }
            else {
                throw new Exception($"Transport {cfg.Transport} is unknow");
            }
        }
    }
}
