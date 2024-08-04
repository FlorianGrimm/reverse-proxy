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
internal sealed class TransportTunnelHttp2ConnectionListenerFactory
    : IConnectionListenerFactory
#if NET8_0_OR_GREATER
    , IConnectionListenerFactorySelector
#endif
{
    private readonly TransportTunnelHttp2Options _options;
    private readonly ILazyRequiredServiceResolver<IProxyStateLookup> _proxyConfigManagerLazy;
    private readonly TransportTunnelHttp2Authentication _transportTunnelHttp2Authentication;
    private readonly ILogger _logger;

    public TransportTunnelHttp2ConnectionListenerFactory(
        IOptions<TransportTunnelHttp2Options> options,
        ILazyRequiredServiceResolver<IProxyStateLookup> proxyConfigManagerLazy,
        TransportTunnelHttp2Authentication transportTunnelHttp2Authentication,
        ILogger<TransportTunnelHttp2ConnectionListener> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _transportTunnelHttp2Authentication = transportTunnelHttp2Authentication;
        _logger = logger;
    }

#pragma warning disable CA1822 // Mark members as static
    public bool CanBind(EndPoint endpoint)
    {
        return endpoint is UriEndPointHttp2;
    }
#pragma warning restore CA1822 // Mark members as static

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not UriEndPointHttp2 uriEndPointHttp2)
        {
            throw new ArgumentException("Invalid endpoint type", nameof(endpoint));
        }

        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
        var tunnelId = uriEndPointHttp2.TunnelId;
        if (!proxyConfigManager.TryGetTunnel(tunnelId, out var tunnel))
        {
            throw new ArgumentException($"Tunnel: '{tunnelId} not found.'", nameof(endpoint));
        }

        return new(new TransportTunnelHttp2ConnectionListener(
            uriEndPointHttp2,
            tunnel,
            _transportTunnelHttp2Authentication,
            _options,
            _logger));
    }
}
