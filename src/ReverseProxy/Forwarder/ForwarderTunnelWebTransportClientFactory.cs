#if false

TODO: how to

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Forwarder;

internal class ForwarderTunnelWebTransportClientFactory
    : ForwarderTunnelHttpClientFactory
    , IForwarderHttpClientFactory
    , IForwarderHttpClientFactorySelectiv
{
    public const string Transport = "TunnelWebSocket";

    public ForwarderTunnelWebTransportClientFactory(
        IProxyTunnelConfigManager proxyTunnelConfigManager,
        ILogger<ForwarderTunnelWebTransportClientFactory> logger
        )
        : base(proxyTunnelConfigManager, logger) { }

    public override string GetTransport() => Transport;
}
#endif
