// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Configuration.ConfigProvider;

internal sealed class ConfigurationSnapshot : IProxyConfig
{
    public List<RouteConfig> Routes { get; internal set; } = new List<RouteConfig>();

    public List<ClusterConfig> Clusters { get; internal set; } = new List<ClusterConfig>();

    public List<TransportTunnelConfig> Tunnels { get; internal set; } = new List<TransportTunnelConfig>();

    IReadOnlyList<RouteConfig> IProxyConfig.Routes => Routes;

    IReadOnlyList<ClusterConfig> IProxyConfig.Clusters => Clusters;

    IReadOnlyList<TransportTunnelConfig> IProxyConfig.Tunnels => Tunnels;

    // This field is required.
    public IChangeToken ChangeToken { get; internal set; } = default!;
}
