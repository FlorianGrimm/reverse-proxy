// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;
internal sealed class TransportTunnelWebSocketConnectionListenerFactory
    : IConnectionListenerFactory
#if NET8_0_OR_GREATER
    , IConnectionListenerFactorySelector
#endif
{
    private readonly TransportTunnelWebSocketOptions _options;
    private readonly LazyProxyConfigManager _proxyConfigManagerLazy;
    private readonly TransportTunnelWebSocketAuthentication _transportTunnelWebSocketAuthentication;
    private readonly ILogger<TransportTunnelWebSocketConnectionListener> _logger;

    public TransportTunnelWebSocketConnectionListenerFactory(
        IOptions<TransportTunnelWebSocketOptions> options,
        LazyProxyConfigManager proxyConfigManagerLazy,
        TransportTunnelWebSocketAuthentication transportTunnelWebSocketAuthentication,
        ILogger<TransportTunnelWebSocketConnectionListener> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _transportTunnelWebSocketAuthentication = transportTunnelWebSocketAuthentication;
        _logger = logger;
    }

#pragma warning disable CA1822 // Mark members as static
    public bool CanBind(EndPoint endpoint)
    {
        return endpoint is UriWebSocketEndPoint;
    }
#pragma warning restore CA1822 // Mark members as static

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not UriWebSocketEndPoint uriEndpointWebSocket)
        {
            throw new ArgumentException("Invalid endpoint type", nameof(endpoint));
        }

        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
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
