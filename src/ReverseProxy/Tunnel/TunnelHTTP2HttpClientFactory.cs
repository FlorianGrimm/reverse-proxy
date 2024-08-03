// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelHTTP2HttpClientFactory
    : ITransportForwarderHttpClientFactorySelector
{
    private readonly ConcurrentDictionary<string, TunnelHTTP2HttpClientFactoryForCluster> _tunnelHTTP2HttpClientFactoryBoundByClusterId = new();
    private readonly ILazyRequiredServiceResolver<ProxyConfigManager> _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger _logger;

    public TunnelHTTP2HttpClientFactory(
        ILazyRequiredServiceResolver<ProxyConfigManager> proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<TunnelHTTP2HttpClientFactory> logger)
    {
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
    }

    public string GetTransportMode() => "TunnelHTTP2";

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(ForwarderHttpClientContext context)
    {
        while (true)
        {
            if (!_tunnelHTTP2HttpClientFactoryBoundByClusterId.TryGetValue(context.ClusterId, out var result))
            {
                result = new TunnelHTTP2HttpClientFactoryForCluster(
                    _proxyConfigManagerLazy.GetService(),
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
