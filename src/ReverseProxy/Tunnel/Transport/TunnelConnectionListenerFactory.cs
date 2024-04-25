using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;

// TODO: what exactly is a IConnectionListenerFactorySelector

namespace Yarp.ReverseProxy.Tunnel.Transport;

internal class TunnelConnectionListenerFactory : IConnectionListenerFactory
#if NET8_0_OR_GREATER
    , IConnectionListenerFactorySelector
#endif
{
    private readonly TunnelBackendOptions _options;
    private readonly ProxyTunnelConfigManager _proxyTunnelConfigManager;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<TunnelConnectionListenerFactory> _logger;

    public TunnelConnectionListenerFactory(
        IOptions<TunnelBackendOptions> options,
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        ILoggerFactory loggerFactory
        )
    {
        _options = options.Value;
        _proxyTunnelConfigManager = proxyTunnelConfigManager;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<TunnelConnectionListenerFactory>();
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not UriTunnelTransportEndPoint uriTunnelTransportEndPoint)
        {
            throw new NotSupportedException();
        }

        var tunnelId = uriTunnelTransportEndPoint.Uri?.Host;
        if (string.IsNullOrEmpty(tunnelId)) { throw new NotSupportedException(); }

        if (!_proxyTunnelConfigManager.TryGetTunnelBackendToFrontend(tunnelId, out var backendToFrontend))
        {
            Log.TunnelBackendToFrontendNotFound(_logger, tunnelId);
            throw new NotSupportedException();
        }


        // TODO: more di
        Log.TunnelConnectionListenerAdd(_logger, tunnelId, backendToFrontend.Transport, backendToFrontend.Url);

        TunnelConnectionListenerProtocol listener;
        if (backendToFrontend.Transport == "WebSocket")
        {
            listener = new TunnelConnectionListenerWebSocket(
                uriTunnelTransportEndPoint,
                tunnelId, backendToFrontend,
                _proxyTunnelConfigManager,
                _options,
                _loggerFactory.CreateLogger<TunnelConnectionListenerWebSocket>()
                );
        }
        else
        {
            listener = new TunnelConnectionListenerHttp2(
                uriTunnelTransportEndPoint,
                tunnelId, backendToFrontend,
                _proxyTunnelConfigManager,
                _options,
                _loggerFactory.CreateLogger<TunnelConnectionListenerHttp2>()
                );
        }

        return new(listener);
    }

    public bool CanBind(EndPoint endpoint)
    {
        if (endpoint is not UriTunnelTransportEndPoint uriTunnelTransportEndPoint)
        {
            return false;
        }

        var tunnelId = uriTunnelTransportEndPoint.Uri?.Host;
        if (string.IsNullOrEmpty(tunnelId)) {
            return false;
        }

        return true;
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _tunnelBackendToFrontendNotFound = LoggerMessage.Define<string>(
            LogLevel.Warning,
            EventIds.TunnelBackendToFrontendNotFound,
            "TunnelBackendToFrontend '{tunnelId}' was not found.");

        public static void TunnelBackendToFrontendNotFound(ILogger logger, string tunnelId)
        {
            _tunnelBackendToFrontendNotFound(logger, tunnelId, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _tunnelConnectionListenerAdd = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.TunnelConnectionListenerAdd,
            "TunnelConnectionListener '{tunnelId}' as '{transport}' to '{url}' was added.");

        public static void TunnelConnectionListenerAdd(ILogger logger, string tunnelId, string transport, string url)
        {
            _tunnelConnectionListenerAdd(logger, tunnelId, transport, url, null);
        }
    }
}
