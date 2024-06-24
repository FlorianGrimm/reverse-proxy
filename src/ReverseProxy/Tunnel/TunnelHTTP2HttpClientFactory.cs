using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelHTTP2HttpClientFactory
    : ITransportHttpClientFactorySelector
{
    private readonly ConcurrentDictionary<string, TunnelHTTP2HttpClientFactoryForCluster> _tunnelHTTP2HttpClientFactoryBoundByClusterId = new();
    private readonly UnShortCitcuitOnceProxyConfigManager _unShortCitcuitOnceProxyConfigManager;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger _logger;

    public TunnelHTTP2HttpClientFactory(
        UnShortCitcuitOnceProxyConfigManager unShortCitcuitOnceProxyConfigManager,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<TunnelHTTP2HttpClientFactory> logger)
    {
        _unShortCitcuitOnceProxyConfigManager = unShortCitcuitOnceProxyConfigManager;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
    }

    public TransportMode GetTransportMode() => TransportMode.TunnelHTTP2;

    public int GetOrder() => 0;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(
        TransportMode transportMode,
        ForwarderHttpClientContext context)
    {
        while (true)
        {
            if (!_tunnelHTTP2HttpClientFactoryBoundByClusterId.TryGetValue(context.ClusterId, out var result))
            {
                result = new TunnelHTTP2HttpClientFactoryForCluster(
                    _unShortCitcuitOnceProxyConfigManager.GetService(),
                    _tunnelConnectionChannelManager,
                    context.ClusterId,
                    _logger);
                if (_tunnelHTTP2HttpClientFactoryBoundByClusterId.TryAdd(context.ClusterId, result))
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
