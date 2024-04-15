// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Management;

public interface IProxyTunnelStateLookup
{
    IEnumerable<TunnelBackendToFrontendState> GetTunnelBackendToFrontends();
    bool TryGetTunnelBackendToFrontend(string tunnelId, [MaybeNullWhen(false)] out TunnelBackendToFrontendState state);

    IEnumerable<TunnelFrontendToBackendState> GetTunnelFrontendToBackends();
    bool TryGetTunnelFrontendToBackend(string tunnelId, [MaybeNullWhen(false)] out TunnelFrontendToBackendState state);
}

internal sealed class ProxyTunnelConfigManager
    : IProxyTunnelStateLookup
    , IProxyConfigProvider
{

    private readonly List<IProxyTunnelConfigProvider> _configProviders = new();
    private bool _needConstruction = false;
    private ProxyTunnelConfigState _proxyTunnelConfigState = new ProxyTunnelConfigState([], []);
    private ILogger<ProxyTunnelConfigManager> _logger;
    private readonly InMemoryConfigProvider _memoryConfigProvider = new([], []);

    public ProxyTunnelConfigManager()
    {
        _logger = NullLogger<ProxyTunnelConfigManager>.Instance;
    }

    internal void LateInject(IServiceProvider serviceProvider)
    {
        if (_logger is not NullLogger<ProxyTunnelConfigManager>) { return; }
        _logger = serviceProvider.GetRequiredService<ILogger<ProxyTunnelConfigManager>>();
    }

    public void AddConfigProvider(IProxyTunnelConfigProvider tunnelConfigProvider)
    {
        _configProviders.Add(tunnelConfigProvider);
        _needConstruction = true;
    }

    public IEnumerable<TunnelFrontendToBackendState> GetTunnelFrontendToBackends()
    {
        var proxyTunnelConfigState = GetCurrentState();
        return proxyTunnelConfigState.GetTunnelFrontendToBackends();
    }

    public bool TryGetTunnelFrontendToBackend(string tunnelId, [MaybeNullWhen(false)] out TunnelFrontendToBackendState state)
    {
        var proxyTunnelConfigState = GetCurrentState();
        return proxyTunnelConfigState.TryGetTunnelFrontendToBackend(tunnelId, out state);
    }

    public IEnumerable<TunnelBackendToFrontendState> GetTunnelBackendToFrontends()
    {
        var proxyTunnelConfigState = GetCurrentState();
        return proxyTunnelConfigState.GetTunnelBackendToFrontends();
    }

    public bool TryGetTunnelBackendToFrontend(string tunnelId, [MaybeNullWhen(false)] out TunnelBackendToFrontendState state)
    {
        var proxyTunnelConfigState = GetCurrentState();
        return proxyTunnelConfigState.TryGetTunnelBackendToFrontend(tunnelId, out state);
    }

    private ProxyTunnelConfigState GetCurrentState()
    {
        // TODO: need to handle the case where the config providers are updated

        if (_needConstruction)
        {
            lock (this)
            {
                if (_needConstruction)
                {
                    List<TunnelFrontendToBackendState> tunnelFrontendToBackends = new();
                    List<TunnelBackendToFrontendState> tunnelBackendToFrontends = new();

                    foreach (var configProvider in _configProviders)
                    {
                        var tunnelConfig = configProvider.GetTunnelConfig();
                        foreach (var tunnelFrontendToBackendConfig in tunnelConfig.TunnelFrontendToBackends)
                        {
                            tunnelFrontendToBackends.Add(CreateTunnelFrontendToBackend(tunnelFrontendToBackendConfig));
                        }
                        foreach (var tunnelBackendToFrontendConfig in tunnelConfig.TunnelBackendToFrontends)
                        {
                            tunnelBackendToFrontends.Add(CreateTunnelBackendToFrontend(tunnelBackendToFrontendConfig));
                        }
                    }
                    var currentProxyTunnelConfigState = _proxyTunnelConfigState;
                    var nextProxyTunnelConfigState = new ProxyTunnelConfigState(tunnelFrontendToBackends, tunnelBackendToFrontends);

                    _proxyTunnelConfigState = nextProxyTunnelConfigState;
                    _needConstruction = false;

#if TODO
                    {
                        foreach (var current in currentProxyTunnelConfigState.TunnelFrontendToBackendByTunnelId) {
                            if (nextProxyTunnelConfigState.TunnelBackendToFrontendByTunnelId.TryGetValue(current.Key, out var next))
                            {
                                if (next.Equals(current.Value)) {
                                }
                            }
                            else
                            {
                                // removed
                            }
                        }
                    }
#endif
                    UpdateMemoryConfigProvider(_proxyTunnelConfigState);

                    return _proxyTunnelConfigState;
                }
            }
        }
        return _proxyTunnelConfigState;
    }

    internal void UpdateMemoryConfigProvider(ProxyTunnelConfigState? proxyTunnelConfigState)
    {
        proxyTunnelConfigState ??= _proxyTunnelConfigState;

        List<ClusterConfig> clusters = new();

        foreach (var tunnel in proxyTunnelConfigState.TunnelFrontendToBackendByTunnelId.Values)
        {
            var clusterId = tunnel.TunnelId;
            var destinations = TryGetTunnelHandler(clusterId, out var tunnelHandler)
                ? tunnelHandler.GetDestinations()
                : new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase);
            var clusterConfig = new ClusterConfig()
            {
                ClusterId = clusterId,
                Destinations = destinations,
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    { "TunnelId", clusterId }
                }
            };
            clusters.Add(clusterConfig);
        }
        if ((clusters.Count == 0)
            && (_memoryConfigProvider.GetConfig().Clusters.Count == 0))
        {
            // skip
        }
        else
        {
            _memoryConfigProvider.Update([], clusters);
        }
    }

    private TunnelFrontendToBackendState CreateTunnelFrontendToBackend(TunnelFrontendToBackendConfig tunnelFrontendToBackendConfig)
    {
        return new TunnelFrontendToBackendState()
        {
            TunnelId = tunnelFrontendToBackendConfig.TunnelId,
            Transport = tunnelFrontendToBackendConfig.Transport,
            Authentication = new TunnelFrontendToBackendAuthenticationConfig()
        };
    }

    private TunnelBackendToFrontendState CreateTunnelBackendToFrontend(TunnelBackendToFrontendConfig tunnelBackendToFrontendConfig)
    {
        return new TunnelBackendToFrontendState()
        {
            TunnelId = tunnelBackendToFrontendConfig.TunnelId,
            RemoteTunnelId = tunnelBackendToFrontendConfig.RemoteTunnelId,
            Transport = tunnelBackendToFrontendConfig.Transport,
            MaxConnectionCount = tunnelBackendToFrontendConfig.MaxConnectionCount, //??
            Url = tunnelBackendToFrontendConfig.Url,
            Authentication = new TunnelBackendToFrontendAuthenticationConfig()
        };
    }

    private ImmutableDictionary<string, ITunnelHandler> _tunnelHandlers = ImmutableDictionary<string, ITunnelHandler>.Empty;

    internal void AddTunnelHandler(string tunnelId, ITunnelHandler tunnelHandler)
    {
        while (true)
        {
            var currentTunnelHandlers = _tunnelHandlers;
            var nextTunnelHandlers = currentTunnelHandlers.Add(tunnelId, tunnelHandler);
            if (ReferenceEquals(
                System.Threading.Interlocked.CompareExchange(ref _tunnelHandlers, nextTunnelHandlers, currentTunnelHandlers),
                currentTunnelHandlers))
            {
                break;
            }
        }
    }
    internal bool TryGetTunnelHandler(string tunnelId, [MaybeNullWhen(false)] out ITunnelHandler tunnelHandler)
    {
        return _tunnelHandlers.TryGetValue(tunnelId, out tunnelHandler);
    }
    internal void RemoveTunnelHandler(string tunnelId)
    {
        while (true)
        {
            var currentTunnelHandlers = _tunnelHandlers;
            var nextTunnelHandlers = currentTunnelHandlers.Remove(tunnelId);
            if (ReferenceEquals(
                System.Threading.Interlocked.CompareExchange(ref _tunnelHandlers, nextTunnelHandlers, currentTunnelHandlers),
                currentTunnelHandlers))
            {
                break;
            }
        }
    }

    IProxyConfig IProxyConfigProvider.GetConfig()
    {
        return _memoryConfigProvider.GetConfig();
    }
}

internal class ProxyTunnelConfigState : IProxyTunnelStateLookup
{
    public readonly ImmutableDictionary<string, TunnelFrontendToBackendState> TunnelFrontendToBackendByTunnelId;
    public readonly ImmutableDictionary<string, TunnelBackendToFrontendState> TunnelBackendToFrontendByTunnelId;

    public ProxyTunnelConfigState(
        List<TunnelFrontendToBackendState> tunnelFrontendToBackends,
        List<TunnelBackendToFrontendState> tunnelBackendToFrontends)
    {
        Dictionary<string, TunnelFrontendToBackendState> dictTunnelFrontendToBackend = new(StringComparer.OrdinalIgnoreCase);
        foreach (var tunnelFrontendToBackend in tunnelFrontendToBackends)
        {
            dictTunnelFrontendToBackend.Add(tunnelFrontendToBackend.TunnelId, tunnelFrontendToBackend);
        }

        Dictionary<string, TunnelBackendToFrontendState> dictTunnelBackendToFrontend = new(StringComparer.OrdinalIgnoreCase);
        foreach (var tunnelBackendToFrontend in tunnelBackendToFrontends)
        {
            dictTunnelBackendToFrontend.Add(tunnelBackendToFrontend.TunnelId, tunnelBackendToFrontend);
        }

        TunnelFrontendToBackendByTunnelId = dictTunnelFrontendToBackend.ToImmutableDictionary();
        TunnelBackendToFrontendByTunnelId = dictTunnelBackendToFrontend.ToImmutableDictionary();
    }

    public IEnumerable<TunnelFrontendToBackendState> GetTunnelFrontendToBackends()
    {
        return TunnelFrontendToBackendByTunnelId.Values;
    }

    public bool TryGetTunnelFrontendToBackend(string tunnelId, [MaybeNullWhen(false)] out TunnelFrontendToBackendState state)
    {
        return TunnelFrontendToBackendByTunnelId.TryGetValue(tunnelId, out state);
    }


    public IEnumerable<TunnelBackendToFrontendState> GetTunnelBackendToFrontends()
    {
        return TunnelBackendToFrontendByTunnelId.Values;
    }

    public bool TryGetTunnelBackendToFrontend(string tunnelId, [MaybeNullWhen(false)] out TunnelBackendToFrontendState state)
    {
        return TunnelBackendToFrontendByTunnelId.TryGetValue(tunnelId, out state);
    }
}
