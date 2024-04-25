using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Forwarder;

internal class ForwarderTunnelWebSocketClientFactory
    : ForwarderTunnelHttpClientFactory
    , IForwarderHttpClientFactory
    , IForwarderHttpClientFactorySelectiv
{
    public const string Transport = "TunnelWebSocket";

    public ForwarderTunnelWebSocketClientFactory(
        IProxyTunnelConfigManager proxyTunnelConfigManager,
        ILogger<ForwarderTunnelWebSocketClientFactory> logger
        )
        : base(proxyTunnelConfigManager, logger) { }

    public override string GetTransport() => Transport;
}
