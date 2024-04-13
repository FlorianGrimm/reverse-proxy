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

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions for <see cref="IServiceCollection"/>
/// used to register the ReverseProxy's components.
/// </summary>
public static partial class ReverseProxyServiceCollectionExtensions
{
    public static IReverseProxyBuilder UseReverseProxyTunnelBackendToFrontend(
        this IReverseProxyBuilder reverseProxyBuilder,
        IWebHostBuilder webHostBuilder,
        Action<TunnelBackendOptions>? configure = null
        ) {
        reverseProxyBuilder.Services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();
        if (configure is not null)
        {
            reverseProxyBuilder.Services.Configure(configure);
        }

        webHostBuilder.ConfigureKestrel(options =>
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

        return reverseProxyBuilder;
    }
}
