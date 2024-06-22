using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Transport;
internal sealed class TransportTunnelHttp2ConnectionListenerFactory
    : IConnectionListenerFactory
    , IConnectionListenerFactorySelector
{
    private readonly TransportTunnelHttp2Options _options;
    private readonly UnShortCitcuitOnceProxyConfigManager _proxyConfigManagerOnce;
    private readonly ILogger _logger;

    public TransportTunnelHttp2ConnectionListenerFactory(
        IOptions<TransportTunnelHttp2Options> options,
        UnShortCitcuitOnceProxyConfigManager proxyConfigManagerOnce,
        ILogger<TransportTunnelHttp2ConnectionListener> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerOnce = proxyConfigManagerOnce;
        _logger = logger;
    }

    public bool CanBind(EndPoint endpoint)
    {
        return endpoint is UriEndPointHttp2;
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not UriEndPointHttp2 uriEndPointHttp2)
        {
            throw new ArgumentException("Invalid endpoint type", nameof(endpoint));
        }

        var proxyConfigManager = _proxyConfigManagerOnce.GetService();
        var tunnelId = uriEndPointHttp2.TunnelId;
        if (!proxyConfigManager.TryGetTunnel(tunnelId, out var tunnel))
        {
            throw new ArgumentException($"Tunnel: '{tunnelId} not found.'", nameof(endpoint));
        }

        return new(new TransportTunnelHttp2ConnectionListener(
            uriEndPointHttp2,
            tunnel,
            _options,
            _logger));
    }
}
