// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class IReverseProxyTunnelBuilderExtensions {
    /// <summary>
    /// Loads routes and endpoints from config.
    /// </summary>
    public static IReverseProxyTunnelBuilder LoadFromConfig(this IReverseProxyTunnelBuilder builder, IConfiguration config)
    {
        if (config is null)
        {
            throw new ArgumentNullException(nameof(config));
        }

        if (builder is ReverseProxyTunnelBuilder reverseProxyTunnelBuilder)
        {
            var tunnelConfigProvider = new TunnelConfigProvider(config);
            reverseProxyTunnelBuilder.ProxyTunnelConfigManager.AddConfigProvider(tunnelConfigProvider);
        }

        return builder;
    }
}
