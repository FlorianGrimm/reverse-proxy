using System;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.AspNetCore.Builder
{
    public static class WebHostBuilderExtensions
    {
        public static IWebHostBuilder UseReverseProxyTunnelTransport(this IWebHostBuilder hostBuilder,
            string url,
            Action<TunnelOptions>? configure = null)
        {
            ArgumentNullException.ThrowIfNull(url);

            hostBuilder.ConfigureKestrel(options =>
            {
                options.Listen(new UriTunnelTransportEndPoint(new Uri(url)));
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
}
