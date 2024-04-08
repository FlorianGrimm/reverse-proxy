using System;
using System.Collections.Generic;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Transport;

namespace Microsoft.AspNetCore.Builder
{
    public static class WebApplicationBuilderExtensions
    {
        // TODO: InMemoryConfigProvider big uff how to unify this
        public static IReverseProxyBuilder AddReverseProxy(
            this WebApplicationBuilder webApplicationBuilder,
            string configurationPath,
            Action<TunnelOptions>? configureTunnelOptions = null)
        {
            var configurationSection = webApplicationBuilder.Configuration.GetSection(configurationPath);
            return webApplicationBuilder.AddReverseProxy(configurationSection, configureTunnelOptions);
        }

        public static IReverseProxyBuilder AddReverseProxy(
            this WebApplicationBuilder webApplicationBuilder,
            IConfiguration configurationSection,
            Action<TunnelOptions>? configureTunnelOptions = null)
        {
            var reverseProxyBuilder = webApplicationBuilder.Services.AddReverseProxy();

            reverseProxyBuilder.LoadFromConfig(configurationSection);

            // TODO: A less invasive way would be nicer

            using var configurationConfigProvider = new ConfigurationConfigProvider(NullLogger<ConfigurationConfigProvider>.Instance, configurationSection);
            var proxyConfig = configurationConfigProvider.GetConfig();
            if (proxyConfig.Tunnels.Count > 0)
            {
                /*
                HashSet<string>? hsUrl = null;
                foreach (var tunnel in proxyConfig.Tunnels)
                {
                    if (string.IsNullOrEmpty(tunnel.Path)) { continue; }
                    var pathUri = new Uri(tunnel.Path);
                    if (!pathUri.IsAbsoluteUri) { continue; }
                    if (hsUrl is null) { hsUrl = new HashSet<string>(); }
                    hsUrl.Add(tunnel.Path);
                }
                */

                // for the Backend
                HashSet<string>? hsTunnelTransportUrl = null;
                foreach (var tunnel in proxyConfig.Tunnels) {
                    var address = tunnel.GetUrl();
                    if (string.IsNullOrEmpty(address)) { continue; }
                    var pathUri = new Uri(address);
                    if (!pathUri.IsAbsoluteUri) { continue; }
                    if (hsTunnelTransportUrl is null) { hsTunnelTransportUrl = new HashSet<string>(); }
                    hsTunnelTransportUrl.Add(address);
                }
                if (hsTunnelTransportUrl is not null)
                {
                    webApplicationBuilder.WebHost.ConfigureKestrel(options =>
                    {
                        foreach (var url in hsTunnelTransportUrl)
                        {
                            options.Listen(new UriTunnelTransportEndPoint(new Uri(url)));
                        }
                    });

                    webApplicationBuilder.Services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();

                    if (configureTunnelOptions is not null)
                    {
                        webApplicationBuilder.Services.Configure(configureTunnelOptions);
                    }
                }
            }

            return reverseProxyBuilder;
        }
    }
}
