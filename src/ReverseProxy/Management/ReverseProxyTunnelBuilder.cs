// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Management;

/// <summary>
/// Reverse Proxy builder for DI configuration.
/// </summary>
internal sealed class ReverseProxyTunnelBuilder : IReverseProxyTunnelBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ReverseProxyTunnelBuilder"/> class.
    /// </summary>
    /// <param name="services">Services collection.</param>
    /// <param name="proxyTunnelConfigManager">the singleton.</param>
    internal ReverseProxyTunnelBuilder(IServiceCollection services, ProxyTunnelConfigManager proxyTunnelConfigManager)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
        ProxyTunnelConfigManager = proxyTunnelConfigManager;
    }

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    public IServiceCollection Services { get; }

    internal ProxyTunnelConfigManager ProxyTunnelConfigManager { get; }
}
