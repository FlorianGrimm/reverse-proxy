using System;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Transport;
public static class WebHostBuilderExtensions
{
    public static IWebHostBuilder UseTunnelTransportHttp2(this IWebHostBuilder hostBuilder, UriEndPointHttp2 endPoint, Action<TunnelHttp2Options>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endPoint);

        hostBuilder.ConfigureKestrel(options =>
        {
            options.Listen(endPoint);
        });

        return hostBuilder.ConfigureServices(services =>
        {
            services.AddSingleton<IConnectionListenerFactory, TunnelHttp2ConnectionListenerFactory>();

            if (configure is not null)
            {
                services.Configure(configure);
            }
        });
    }

    public static IWebHostBuilder UseTunnelTransportWebSocket(this IWebHostBuilder hostBuilder, UriEndpointWebSocket endPoint, Action<TunnelWebSocketOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(endPoint);

        hostBuilder.ConfigureKestrel(options =>
        {
            options.Listen(endPoint);
        });

        return hostBuilder.ConfigureServices(services =>
        {
            services.AddSingleton<IConnectionListenerFactory, TunnelWebSocketConnectionListenerFactory>();

            if (configure is not null)
            {
                services.Configure(configure);
            }
        });
    }
}
