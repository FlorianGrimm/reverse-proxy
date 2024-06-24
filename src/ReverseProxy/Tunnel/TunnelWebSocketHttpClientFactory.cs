using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Tunnel;
internal sealed class TunnelWebSocketHttpClientFactory
    : ITransportHttpClientFactorySelector
{
    private readonly ConcurrentDictionary<string, TunnelWebSocketHttpClientFactoryForCluster> _tunnelWebSocketHttpClientFactoryBoundByClusterId = new();
    private readonly UnShortCitcuitOnceProxyConfigManager _unShortCitcuitOnceProxyConfigManager;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger _logger;

    public TunnelWebSocketHttpClientFactory(
        UnShortCitcuitOnceProxyConfigManager unShortCitcuitOnceProxyConfigManager,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<TunnelWebSocketHttpClientFactory> logger)
    {
        _unShortCitcuitOnceProxyConfigManager = unShortCitcuitOnceProxyConfigManager;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
    }

    public TransportMode GetTransportMode() => TransportMode.TunnelWebSocket;

    public int GetOrder() => 0;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(
        TransportMode transportMode,
        ForwarderHttpClientContext context)
    {
        while (true)
        {
            if (!_tunnelWebSocketHttpClientFactoryBoundByClusterId.TryGetValue(context.ClusterId, out var result))
            {
                result = new TunnelWebSocketHttpClientFactoryForCluster(
                    _unShortCitcuitOnceProxyConfigManager.GetService(),
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
