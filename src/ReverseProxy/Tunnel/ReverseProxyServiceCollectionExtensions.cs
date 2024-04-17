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

using Yarp.ReverseProxy;
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
        reverseProxyBuilder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>());
        //reverseProxyBuilder.Services.AddSingleton<IConnectionListenerFactory, TunnelConnectionListenerFactory>();
        if (configure is not null)
        {
            reverseProxyBuilder.Services.Configure(configure);
        }

        webHostBuilder.ConfigureKestrel(options =>
        {
            // using ProxyConfigManager is not possible here, since Kestrel is being created now.
            var proxyTunnelConfigManager = options.ApplicationServices.GetRequiredService<ProxyTunnelConfigManager>();
            var logger = options.ApplicationServices.GetRequiredService<ILogger<TunnelConnectionListenerFactory>>();
            if (proxyTunnelConfigManager is not null)
            {
                if (proxyTunnelConfigManager.GetTunnelBackendToFrontends().Any())
                {
                    foreach (var tunnelBackendToFrontend in proxyTunnelConfigManager.GetTunnelBackendToFrontends())
                    {
                        Log.TunnelBackendToFrontendAdd(logger, tunnelBackendToFrontend.TunnelId, tunnelBackendToFrontend.RemoteTunnelId, tunnelBackendToFrontend.Url, tunnelBackendToFrontend.Transport);

                        var url = $"https://{tunnelBackendToFrontend.TunnelId}";
                        options.Listen(new UriTunnelTransportEndPoint(new Uri(url)));
                    }
                }
            }
        });


        return reverseProxyBuilder;
    }

    private static partial class Log
    {
        private static readonly Action<ILogger, string, string, string, string, Exception?> _tunnelBackendToFrontendAdd = LoggerMessage.Define<string, string, string, string>(
            LogLevel.Debug,
            EventIds.TunnelBackendToFrontendAdd,
            "TunnelBackendToFrontend '{tunnelId}' to '{remoteTunnelId}' via '{url}' with '{transport}' has been added.");

        public static void TunnelBackendToFrontendAdd(ILogger logger, string tunnelId, string remoteTunnelId, string url, string transport)
        {
            _tunnelBackendToFrontendAdd(logger, tunnelId, remoteTunnelId, url, transport, null);
        }
        /*
        private static readonly Action<ILogger, string, Exception?> _clusterAdded = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.ClusterAdded,
            "Cluster '{clusterId}' has been added.");

        public static void ClusterAdded(ILogger logger, string clusterId)
        {
            _clusterAdded(logger, clusterId, null);
        }
        */
    }
}
