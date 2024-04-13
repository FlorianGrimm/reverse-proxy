// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Configuration.ConfigProvider;

internal sealed class ConfigurationSnapshot : IProxyConfig
{
    public List<RouteConfig> Routes { get; internal set; } = new List<RouteConfig>();

    public List<ClusterConfig> Clusters { get; internal set; } = new List<ClusterConfig>();

    public List<TunnelFrontendToBackendConfig> TunnelFrontendToBackends { get; internal set; } = new List<TunnelFrontendToBackendConfig>();

    public List<TunnelBackendToFrontendConfig> TunnelBackendToFrontends { get; internal set; } = new List<TunnelBackendToFrontendConfig>();

    IReadOnlyList<RouteConfig> IProxyConfig.Routes => Routes;

    IReadOnlyList<ClusterConfig> IProxyConfig.Clusters => Clusters;

    IReadOnlyList<TunnelFrontendToBackendConfig> IProxyConfig.TunnelFrontendToBackends => TunnelFrontendToBackends;

    IReadOnlyList<TunnelBackendToFrontendConfig> IProxyConfig.TunnelBackendToFrontends => TunnelBackendToFrontends;

    // This field is required.
    public IChangeToken ChangeToken { get; internal set; } = default!;

}
