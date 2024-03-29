using System;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy.Tunnel.Backend;

namespace Microsoft.AspNetCore.Hosting;

public static class YarpTunnelWebHostBuilderExtensions
{
    public static IWebHostBuilder UseTunnelTransport(this IWebHostBuilder hostBuilder, string url, Action<TunnelOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(url);

        hostBuilder.ConfigureKestrel(options =>
        {
            options.Listen(new UriEndPoint2(new Uri(url)));
        });

        return hostBuilder.ConfigureServices(services =>
        {
            services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();

            if (configure is not null)
            {
                services.Configure(configure);
            }
        });
    }
}
