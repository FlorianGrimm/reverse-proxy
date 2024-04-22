// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Threading;

using Microsoft.AspNetCore.Components.Routing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Configuration.TunnelValidators;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Routing;
using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Management;

public interface IProxyTunnelStateLookup
{
    IEnumerable<TunnelBackendToFrontendState> GetTunnelBackendToFrontends();
    bool TryGetTunnelBackendToFrontend(string tunnelId, [MaybeNullWhen(false)] out TunnelBackendToFrontendState state);

    IEnumerable<TunnelFrontendToBackendState> GetTunnelFrontendToBackends();
    bool TryGetTunnelFrontendToBackend(string tunnelId, [MaybeNullWhen(false)] out TunnelFrontendToBackendState state);
}

public interface IProxyTunnelConfigManager : IProxyTunnelStateLookup
{
    bool TryGetTunnelHandler(string tunnelId, [MaybeNullWhen(false)] out ITunnelHandler tunnelHandler);
}

internal sealed class ProxyTunnelConfigManager
    : IProxyTunnelStateLookup
    , IProxyTunnelConfigManager
    , IProxyConfigProvider
{
    private readonly object _syncRoot = new();

    private ProxyTunnelConfigState _proxyTunnelConfigState = new ProxyTunnelConfigState([], []);
    private bool _needConstruction = false;
    private readonly List<IProxyTunnelConfigProvider> _configProviders = new();
    private IProxyTunnelConfigValidator _configValidator = new ProxyTunnelConfigValidator([], []);
    private readonly InMemoryConfigProvider _memoryConfigProvider = new([], []);
    private readonly ConcurrentDictionary<string, string> _tunnelChannelIdTunnelBackendToFrontend = new(StringComparer.OrdinalIgnoreCase);

    // by Initialize
    private ILogger<ProxyTunnelConfigManager> _logger;

    /// <summary>
    /// The ProxyTunnelConfigManager is create before the services are available.
    /// </summary>
    public ProxyTunnelConfigManager()
    {
        _logger = NullLogger<ProxyTunnelConfigManager>.Instance;
    }

    internal void Initialize(IServiceProvider serviceProvider)
    {
        if (_logger is not NullLogger<ProxyTunnelConfigManager>) { return; }
        _logger = serviceProvider.GetRequiredService<ILogger<ProxyTunnelConfigManager>>();
        _configValidator = serviceProvider.GetRequiredService<IProxyTunnelConfigValidator>();
        GetCurrentState();
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
                    var nextProxyTunnelConfigState = CreateTunnelConfigState();

                    _proxyTunnelConfigState = nextProxyTunnelConfigState;
                    _needConstruction = false;
                    UpdateMemoryConfigProvider(nextProxyTunnelConfigState);

                    // TODO: need to handle the changes?? How is it possible that this is called multiple times?

                    return _proxyTunnelConfigState;
                }
            }
        }
        return _proxyTunnelConfigState;
    }

    private ProxyTunnelConfigState CreateTunnelConfigState()
    {
        List<TunnelFrontendToBackendState> tunnelFrontendToBackends = new();
        List<TunnelBackendToFrontendState> tunnelBackendToFrontends = new();

        List<Exception> errors = new();
        foreach (var configProvider in _configProviders)
        {
            var tunnelConfig = configProvider.GetTunnelConfig();
            foreach (var tunnelFrontendToBackendConfig in tunnelConfig.TunnelFrontendToBackends)
            {
                _configValidator.ValidateTunnelFrontendToBackendConfig(tunnelFrontendToBackendConfig, errors);
                tunnelFrontendToBackends.Add(CreateTunnelFrontendToBackend(tunnelFrontendToBackendConfig));
            }
            foreach (var tunnelBackendToFrontendConfig in tunnelConfig.TunnelBackendToFrontends)
            {
                _configValidator.ValidateTunnelBackendToFrontendConfig(tunnelBackendToFrontendConfig, errors);
                var tunnelChannelId = _tunnelChannelIdTunnelBackendToFrontend.GetOrAdd($"{tunnelBackendToFrontendConfig.Url}-{tunnelBackendToFrontendConfig.TunnelId}-{tunnelBackendToFrontendConfig.RemoteTunnelId}-{tunnelBackendToFrontendConfig.Transport}", (_) => Guid.NewGuid().ToString("n"));
                tunnelBackendToFrontends.Add(CreateTunnelBackendToFrontend(tunnelBackendToFrontendConfig, tunnelChannelId));
            }
        }

        if (errors.Count > 0)
        {
            throw new AggregateException("The proxy tunnel config is invalid.", errors);
        }

        var currentProxyTunnelConfigState = _proxyTunnelConfigState;
        var nextProxyTunnelConfigState = new ProxyTunnelConfigState(tunnelFrontendToBackends, tunnelBackendToFrontends);
        return nextProxyTunnelConfigState;
    }

    internal void UpdateMemoryConfigProvider(ProxyTunnelConfigState? proxyTunnelConfigState)
    {
        lock (_syncRoot)
        {
            proxyTunnelConfigState ??= _proxyTunnelConfigState;
            List<RouteConfig> routes = new();
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
                // TODO: TransformBuilderContext uses routes and clusters - so it might be easier to just use the existing classes.
                _memoryConfigProvider.Update([], clusters);
            }
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


    private static string? _Hostname;
    private static string GetHostname()
    {
        if (string.IsNullOrEmpty(_Hostname))
        {
            return _Hostname = System.Environment.GetEnvironmentVariable("COMPUTERNAME") ?? string.Empty;
        }
        else
        {
            return _Hostname;
        }
    }

    private TunnelBackendToFrontendState CreateTunnelBackendToFrontend(TunnelBackendToFrontendConfig tunnelBackendToFrontendConfig, string tunnelChannelId)
    {
        var hostname = !string.IsNullOrEmpty(tunnelBackendToFrontendConfig.Hostname)
            ? tunnelBackendToFrontendConfig.Hostname
            : GetHostname();
        var remoteHost = $"{tunnelBackendToFrontendConfig.TunnelId}-{tunnelChannelId}-{hostname}";

        return new TunnelBackendToFrontendState()
        {
            TunnelChannelId = tunnelChannelId,
            TunnelId = tunnelBackendToFrontendConfig.TunnelId,
            Transport = tunnelBackendToFrontendConfig.Transport,
            RemoteTunnelId = tunnelBackendToFrontendConfig.RemoteTunnelId!,
            MaxConnectionCount = tunnelBackendToFrontendConfig.MaxConnectionCount, //??
            Url = tunnelBackendToFrontendConfig.Url,
            RemoteHost = remoteHost,
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
                Log.TunnelHandlerAdded(_logger, tunnelId, tunnelHandler.GetTransport());
                break;
            }
        }
    }

    public bool TryGetTunnelHandler(string tunnelId, [MaybeNullWhen(false)] out ITunnelHandler tunnelHandler)
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
        GetCurrentState();
        return _memoryConfigProvider.GetConfig();
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, string, Exception?> _tunnelHandlerAdded = LoggerMessage.Define<string, string>(
            LogLevel.Debug,
            EventIds.TunnelHandlerAdded,
            "TunnelHandler '{tunnelId}' as '{transport}' has been added.");
        public static void TunnelHandlerAdded(ILogger logger, string tunnelId, string transport)
        {
            _tunnelHandlerAdded(logger, tunnelId, transport, null);
        }
    }
}
