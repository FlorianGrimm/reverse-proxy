// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Configuration.TunnelValidators;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static partial class ReverseProxyTunnelServiceCollectionExtensions
{
    internal static ProxyTunnelConfigManager AddReverseProxyTunnelConfigManager(this IServiceCollection services) {
        var proxyTunnelConfigManager = services.LastOrDefault(
        (sd) =>
            sd.ImplementationInstance is not null
            && typeof(ProxyTunnelConfigManager).Equals(sd.ServiceType)
    )?.ImplementationInstance as ProxyTunnelConfigManager;

        if (proxyTunnelConfigManager is null)
        {
            proxyTunnelConfigManager = new ProxyTunnelConfigManager();
            services.AddSingleton<IProxyTunnelStateLookup>(proxyTunnelConfigManager);
            services.AddSingleton<IProxyTunnelConfigManager>(proxyTunnelConfigManager);            
            services.AddSingleton<ProxyTunnelConfigManager>(proxyTunnelConfigManager);
            services.AddSingleton<IProxyConfigProvider>(proxyTunnelConfigManager);
            services.AddSingleton<IProxyTunnelConfigValidator, ProxyTunnelConfigValidator>();
            services.AddSingleton<IProxyTunnelBackendToFrontendConfigValidator, ProxyTunnelBackendToFrontendConfigValidator>();
            services.AddSingleton<IProxyTunnelFrontendToBackendConfigValidator, ProxyTunnelFrontendToBackendConfigValidator>();
        }
        return proxyTunnelConfigManager;
    }
    public static IReverseProxyTunnelBuilder AddReverseProxyTunnel(this IServiceCollection services)
    {
        var proxyTunnelConfigManager = AddReverseProxyTunnelConfigManager(services);
        services.AddSingleton<TunnelHandlerFactorySelector>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelHandlerFactory, TunnelHTTP2MapHandlerFactory>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IForwarderHttpClientFactorySelectiv, ForwarderTunnelHTTP2ClientFactory>());
        services.TryAddSingleton<ForwarderTunnelHTTP2ClientFactory, ForwarderTunnelHTTP2ClientFactory>();

        return new ReverseProxyTunnelBuilder(services, proxyTunnelConfigManager);
    }

}
