using System.Collections.Generic;

using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Configuration.ConfigProvider;

internal class TunnelConfigurationSnapshot : IProxyTunnelConfig
{
    public List<TunnelFrontendToBackendConfig> TunnelFrontendToBackends { get; } = new();

    public List<TunnelBackendToFrontendConfig> TunnelBackendToFrontends { get; } = new();

    IReadOnlyList<TunnelFrontendToBackendConfig> IProxyTunnelConfig.TunnelFrontendToBackends => TunnelFrontendToBackends;

    IReadOnlyList<TunnelBackendToFrontendConfig> IProxyTunnelConfig.TunnelBackendToFrontends => TunnelBackendToFrontends;

    public IChangeToken ChangeToken { get; internal set; } = default!;
}
