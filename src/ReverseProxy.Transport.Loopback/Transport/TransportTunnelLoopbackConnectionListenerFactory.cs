using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Transport;

internal class TransportTunnelLoopbackConnectionListenerFactory
    : IConnectionListenerFactory
#if NET8_0_OR_GREATER
    , IConnectionListenerFactorySelector
#endif
{
    private readonly TransportTunnelLoopbackOptions _options;
    private readonly LazyProxyConfigManager _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly TransportTunnelLoopbackAuthenticator _authenticator;
    private readonly ILogger _logger;

    public TransportTunnelLoopbackConnectionListenerFactory(
        IOptions<TransportTunnelLoopbackOptions> options,
        LazyProxyConfigManager proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        TransportTunnelLoopbackAuthenticator authenticator,
        ILogger<TransportTunnelLoopbackConnectionListener> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _authenticator = authenticator;
        _logger = logger;
    }

#pragma warning disable CA1822 // Mark members as static
    public bool CanBind(EndPoint endpoint)
    {
        return endpoint is LoopbackEndPoint;
    }
#pragma warning restore CA1822 // Mark members as static

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not LoopbackEndPoint uriEndPointHttp2)
        {
            throw new ArgumentException("Invalid endpoint type", nameof(endpoint));
        }

        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
        var tunnelId = uriEndPointHttp2.TunnelId;
        if (!proxyConfigManager.TryGetTunnel(tunnelId, out var tunnel))
        {
            throw new ArgumentException($"Tunnel: '{tunnelId} not found.'", nameof(endpoint));
        }

        return new(new TransportTunnelLoopbackConnectionListener(
            uriEndPointHttp2,
            tunnel,
            _tunnelConnectionChannelManager,
            _authenticator,
            _options,
            _logger));
    }

}
