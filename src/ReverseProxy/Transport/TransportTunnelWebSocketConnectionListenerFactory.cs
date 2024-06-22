using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Transport;
internal sealed class TransportTunnelWebSocketConnectionListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    private readonly TransportTunnelWebSocketOptions _options;
    private readonly UnShortCitcuitOnceProxyConfigManager _proxyConfigManagerOnce;
    private readonly TransportTunnelWebSocketAuthentication _transportTunnelWebSocketAuthentication;
    private readonly ILogger<TransportTunnelWebSocketConnectionListener> _logger;

    public TransportTunnelWebSocketConnectionListenerFactory(
        IOptions<TransportTunnelWebSocketOptions> options,
        UnShortCitcuitOnceProxyConfigManager proxyConfigManagerOnce,
        TransportTunnelWebSocketAuthentication transportTunnelWebSocketAuthentication,
        ILogger<TransportTunnelWebSocketConnectionListener> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerOnce = proxyConfigManagerOnce;
        _transportTunnelWebSocketAuthentication = transportTunnelWebSocketAuthentication;
        _logger = logger;
    }

    public bool CanBind(EndPoint endpoint)
    {
        return endpoint is UriWebSocketEndPoint;
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not UriWebSocketEndPoint uriEndpointWebSocket)
        {
            throw new ArgumentException("Invalid endpoint type", nameof(endpoint));
        }

        var proxyConfigManager = _proxyConfigManagerOnce.GetService();
        var tunnelId = uriEndpointWebSocket.TunnelId;
        if (!proxyConfigManager.TryGetTunnel(tunnelId, out var tunnel))
        {
            throw new ArgumentException($"Tunnel: '{tunnelId} not found.'", nameof(endpoint));
        }

        return new(new TransportTunnelWebSocketConnectionListener(
            uriEndpointWebSocket,
            tunnel,
            _transportTunnelWebSocketAuthentication,
            _options,
            _logger
            ));
    }
}
