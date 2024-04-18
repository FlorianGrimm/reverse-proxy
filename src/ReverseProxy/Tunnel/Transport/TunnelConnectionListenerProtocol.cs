using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel.Transport;

internal abstract class TunnelConnectionListenerProtocol : IConnectionListener
{
    protected readonly UriTunnelTransportEndPoint _uriTunnelTransportEndPoint;
    protected readonly string _tunnelId;
    protected readonly TunnelBackendToFrontendState _backendToFrontend;
    protected readonly ProxyTunnelConfigManager _proxyTunnelConfigManager;
    protected readonly TunnelBackendOptions _options;
    protected readonly ILogger _logger;
    protected readonly SemaphoreSlim _connectionLock;
    protected readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    protected readonly CancellationTokenSource _closedCts = new();
    protected readonly HttpMessageInvoker invoker;

    public TunnelConnectionListenerProtocol(
        UriTunnelTransportEndPoint uriTunnelTransportEndPoint,
        string tunnelId,
        TunnelBackendToFrontendState backendToFrontend,
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        TunnelBackendOptions options,
        ILogger logger)
    {
        _uriTunnelTransportEndPoint = uriTunnelTransportEndPoint;
        _tunnelId = tunnelId;
        _backendToFrontend = backendToFrontend;
        _proxyTunnelConfigManager = proxyTunnelConfigManager;
        _options = options;
        _logger = logger;
        _connectionLock = new(options.MaxConnectionCount);

        invoker = new HttpMessageInvoker(
           new SocketsHttpHandler
           {
               EnableMultipleHttp2Connections = true,
               PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
               PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan
           });

    }

    public EndPoint EndPoint => _uriTunnelTransportEndPoint;

    public abstract ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default);

#if false
    public virtual ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var tunnelId = _backendToFrontend.TunnelId;
            if (!_proxyTunnelConfigManager.TryGetTunnelBackendToFrontend(tunnelId, out var tunnel))
            {
                // TODO: create Validator
                throw new ArgumentException($"Tunnel {tunnel} not found");
            }

            var url = _backendToFrontend.Url;
            var remoteTunnelId = _backendToFrontend.RemoteTunnelId;
            var uri = new Uri(new Uri(url), $"/Tunnel/HTTP2/{remoteTunnelId}/{tunnelId}");


            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

            // Kestrel will keep an active accept call open as long as the transport is active
            await _connectionLock.WaitAsync(cancellationToken);

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    /*
                    var connection = new TrackLifetimeConnectionContext(_options.Transport switch
                    {
                        TransportType.WebSockets => await WebSocketConnectionContext.ConnectAsync(Uri, cancellationToken),
                        TransportType.HTTP2 => await HttpClientConnectionContext.ConnectAsync(_httpMessageInvoker, Uri, cancellationToken),
                        _ => throw new NotSupportedException(),
                    });
                    */
                    var connection = await HttpClientConnectionContext.ConnectAsync(_httpMessageInvoker, uri, cancellationToken);

                    // Track this connection lifetime
                    _connections.TryAdd(connection, connection);

                    _ = Task.Run(async () =>
                    {
                        // When the connection is disposed, release it
                        await connection.ExecutionTask;

                        _connections.TryRemove(connection, out _);

                        // Allow more connections in
                        _connectionLock.Release();
                    },
                    cancellationToken);

                    return connection;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // TODO: More sophisticated backoff and retry
                    await Task.Delay(5000, cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

#endif

    protected abstract Uri GetRemoteUrl(TunnelBackendToFrontendState tunnel);

    protected abstract Task<TrackLifetimeConnectionContext> ConnectAsync(HttpMessageInvoker httpMessageInvoker, Uri uri, CancellationToken cancellationToken);

    public async ValueTask DisposeAsync()
    {
        List<Task>? tasks = null;

        foreach (var (_, connection) in _connections)
        {
            tasks ??= new();
            tasks.Add(connection.DisposeAsync().AsTask());
        }

        if (tasks is null)
        {
            return;
        }

        await Task.WhenAll(tasks);
    }

    public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        _closedCts.Cancel();

        foreach (var (_, connection) in _connections)
        {
            // REVIEW: Graceful?
            connection.Abort();
        }

        return ValueTask.CompletedTask;
    }

    protected static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _tunnelBackendToFrontendNotFound = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.TunnelBackendToFrontendNotFound,
            "TunnelBackendToFrontend '{tunnelId}' was not found.");

        public static void TunnelBackendToFrontendNotFound(ILogger logger, string tunnelId)
        {
            _tunnelBackendToFrontendNotFound(logger, tunnelId, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _tunnelConnectionListenerAccept = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.TunnelConnectionListenerAccept,
            "TunnelConnectionListener '{tunnelId}' as '{transport}' to '{url}' is starting.");

        public static void TunnelConnectionListenerAccept(ILogger logger, string tunnelId, string transport, string url)
        {
            _tunnelConnectionListenerAccept(logger, tunnelId, transport, url, null);
        }
    }

}


// public class TunnelConnectionListenerWebTransport: TunnelConnectionListenerProtocol { }
