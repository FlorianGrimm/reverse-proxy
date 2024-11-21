// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Tunnel;
internal sealed class TunnelWebSocketHttpClientFactory
    : ITransportForwarderHttpClientFactorySelector
{
    private readonly ConcurrentDictionary<string, TunnelWebSocketHttpClientFactoryForCluster> _tunnelWebSocketHttpClientFactoryBoundByClusterId = new();
    private readonly LazyProxyConfigManager _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger _logger;

    public TunnelWebSocketHttpClientFactory(
        LazyProxyConfigManager proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<TunnelWebSocketHttpClientFactory> logger)
    {
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
    }

    public string GetTransport()
        => Yarp.ReverseProxy.Tunnel.TunnelConstants.TransportNameTunnelWebSocket;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(ForwarderHttpClientContext context)
    {
        while (true)
        {
            if (!_tunnelWebSocketHttpClientFactoryBoundByClusterId.TryGetValue(context.ClusterId, out var result))
            {
                result = new TunnelWebSocketHttpClientFactoryForCluster(
                    //_proxyConfigManagerLazy.GetService(),
                    _tunnelConnectionChannelManager,
                    context.ClusterId,
                    _logger);
                if (_tunnelWebSocketHttpClientFactoryBoundByClusterId.TryAdd(context.ClusterId, result))
                {
                    return result;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                return result;
            }
        }
    }
}
