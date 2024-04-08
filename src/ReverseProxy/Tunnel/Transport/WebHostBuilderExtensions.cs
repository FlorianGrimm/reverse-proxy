using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Tunnel.Transport;

namespace Microsoft.AspNetCore.Hosting;

public static class YarpTunnelWebHostBuilderExtensions
{
    public static IWebHostBuilder UseTunnelTransport(this IWebHostBuilder hostBuilder, IConfiguration configuration, Action<TunnelBackendConfig>? configure = null)
    {
        var config = TunnelBackendConfigProvider.GetTunnelBackendConfig(configuration);
        if (configure is not null) {
            configure(config);
        }
        hostBuilder.ConfigureKestrel(options =>
        {
            options.Listen(new UriEndPoint2(new Uri(config.Url)));
        });

        return hostBuilder.ConfigureServices(services =>
        {
            services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();
            services.TryAddSingleton<IOptions<TunnelBackendConfig>>(Options.Create(config));
            //if (configure is not null)
            //{
            //    services.Configure(configure);
            //}
        });
    }

    public static IWebHostBuilder UseTunnelTransport(this IWebHostBuilder hostBuilder, TunnelBackendConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(config.Url);

        hostBuilder.ConfigureKestrel(options =>
        {
            options.Listen(new UriEndPoint2(new Uri(config.Url)));
        });

        return hostBuilder.ConfigureServices(services =>
        {
            services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();
            services.TryAddSingleton<IOptions<TunnelBackendConfig>>(Options.Create(config));
        });
    }

    //public static IWebHostBuilder UseTunnelTransport(this IWebHostBuilder hostBuilder, string url, Action<TunnelBackendConfig>? configure = null)
    //{
    //    ArgumentNullException.ThrowIfNull(url);

    //    hostBuilder.ConfigureKestrel(options =>
    //    {
    //        options.Listen(new UriEndPoint2(new Uri(url)));
    //    });

    //    return hostBuilder.ConfigureServices(services =>
    //    {
    //        services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();

    //        if (configure is not null)
    //        {
    //            services.Configure(configure);
    //        }
    //    });
    //}
}
