// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Routing;
using Yarp.ReverseProxy.ServiceDiscovery;
using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Tunnel;
using Yarp.ReverseProxy.Tunnel.Transport;

namespace Microsoft.Extensions.DependencyInjection;

public static partial class ReverseProxyServiceCollectionExtensions
{
    public static IReverseProxyTunnelBuilder UseReverseProxyTunnelBackendToFrontend(
        this IReverseProxyTunnelBuilder reverseProxyBuilder,
        IWebHostBuilder webHostBuilder,
        Action<TunnelBackendOptions>? configure = null
        )
    {
        reverseProxyBuilder.Services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();
        if (configure is not null)
        {
            reverseProxyBuilder.Services.Configure(configure);
        }

        webHostBuilder.ConfigureKestrel(options =>
        {
            // using ProxyConfigManager is not possible here, since Kestrel is being created now.
            var proxyTunnelConfigManager = options.ApplicationServices.GetRequiredService<ProxyTunnelConfigManager>();
            if (proxyTunnelConfigManager is not null)
            {
                foreach (var tunnelBackendToFrontend in proxyTunnelConfigManager.GetTunnelBackendToFrontends())
                {
                    var url = $"https://{tunnelBackendToFrontend.TunnelId}";
                    options.Listen(new UriTunnelTransportEndPoint(new Uri(url)));
                }
            }
        });
        

        return reverseProxyBuilder;
    }
}
