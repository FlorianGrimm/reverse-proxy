#if false
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.AspNetCore.Hosting
{
    public static class WebHostBuilderReverseProxyExtensions
    {
        public static IWebHostBuilder UseReverseProxyTunnelBackend(
            this IWebHostBuilder hostBuilder,
            Action<TunnelBackendOptions>? configure = null
            )
        {
            hostBuilder.ConfigureServices(services =>
            {
                services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();

                if (configure is not null)
                {
                    services.Configure(configure);
                }
            });

            hostBuilder.ConfigureKestrel(options =>
            {
                // using ProxyConfigManager is not possible here, since Kestrel is being created now.
                var proxyConfigProviders = options.ApplicationServices.GetServices<IProxyConfigProvider>();
                if (proxyConfigProviders is not null)
                {
                    foreach (var proxyConfigProvider in proxyConfigProviders)
                    {
                        foreach (var tunnelBackend in proxyConfigProvider.GetConfig().TunnelBackendToFrontends)
                        {
                            var url = $"tunnel://{tunnelBackend.TunnelId}";
                            options.Listen(new UriTunnelTransportEndPoint(new Uri(url)));
                        }
                    }
                }
            });
            return hostBuilder;
        }
    }
}
#endif
