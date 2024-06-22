using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;

using Yarp.ReverseProxy.Transport;

namespace Microsoft.AspNetCore.Builder;

public static class WebHostBuilderExtensions
{
    /// <summary>
    /// Enable the tunnel transport on the backend.
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="webApplicationBuilder"></param>
    /// <param name="configureTunnelHttp2"></param>
    /// <param name="configureTunnelWebSocket"></param>
    /// <returns></returns>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .UseTunnelTransport(builder);
    /// </example>
    public static IReverseProxyBuilder UseTunnelTransport(
        this IReverseProxyBuilder builder,
        WebApplicationBuilder webApplicationBuilder,
        Action<TransportTunnelHttp2Options>? configureTunnelHttp2 = null,
        Action<TransportTunnelWebSocketOptions>? configureTunnelWebSocket = null
        )
    {
        builder.Services.AddSingleton<IConnectionListenerFactory, TransportTunnelHttp2ConnectionListenerFactory>();
        builder.Services.AddSingleton<IConnectionListenerFactory, TransportTunnelWebSocketConnectionListenerFactory>();

        if (configureTunnelHttp2 is not null)
        {
            builder.Services.Configure(configureTunnelHttp2);
        }

        if (configureTunnelWebSocket is not null)
        {
            builder.Services.Configure(configureTunnelWebSocket);
        }

        webApplicationBuilder.WebHost.ConfigureKestrel(options => {
            var proxyConfigManager = options.ApplicationServices.GetRequiredService<ProxyConfigManager>();
            var tunnels = proxyConfigManager.GetTransportTunnels();
            foreach (var tunnel in tunnels)
            {
                var cfg = tunnel.Model.Config;
                var remoteTunnelId = cfg.GetRemoteTunnelId();
                var host = cfg.Url.TrimEnd('/');

                var uriTunnel = new Uri($"{host}/_Tunnel/{remoteTunnelId}");
                var transport = cfg.Transport;
                if (transport == TransportMode.TunnelHTTP2)
                {
                    options.Listen(new UriEndPointHttp2(uriTunnel, tunnel.TunnelId));
                    continue;
                }
                if (transport == TransportMode.TunnelWebSocket)
                {
                    options.Listen(new UriWebSocketEndPoint(uriTunnel, tunnel.TunnelId));
                    continue;
                }
            }
        });
        return builder;
    }
}
