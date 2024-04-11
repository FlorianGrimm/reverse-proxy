// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Configuration.ConfigProvider;

internal sealed class ConfigurationSnapshot : IProxyConfig
{
    public List<RouteConfig> Routes { get; internal set; } = new List<RouteConfig>();

    public List<ClusterConfig> Clusters { get; internal set; } = new List<ClusterConfig>();

    public List<TunnelFrontendConfig> TunnelFrontends { get; internal set; } = new List<TunnelFrontendConfig>();

    public List<TunnelBackendConfig> TunnelBackends { get; internal set; } = new List<TunnelBackendConfig>();

    IReadOnlyList<RouteConfig> IProxyConfig.Routes => Routes;

    IReadOnlyList<ClusterConfig> IProxyConfig.Clusters => Clusters;

    IReadOnlyList<TunnelFrontendConfig> IProxyConfig.TunnelFrontends => TunnelFrontends;

    IReadOnlyList<TunnelBackendConfig> IProxyConfig.TunnelBackends => TunnelBackends;

    // This field is required.
    public IChangeToken ChangeToken { get; internal set; } = default!;

}
