using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel
{
    /// <summary>
    /// This has the core logic that creates and maintains connections to the proxy.
    /// </summary>
    internal class TunnelConnectionListener : IConnectionListener
    {
        private readonly SemaphoreSlim _connectionLock;
        private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
        private readonly TunnelBackendOptions _options;
        private readonly IProxyStateLookup _proxyStateLookup;
        private readonly CancellationTokenSource _closedCts = new();
        private readonly HttpMessageInvoker _httpMessageInvoker;

        public TunnelConnectionListener(TunnelBackendOptions options, IProxyStateLookup proxyStateLookup, EndPoint endpoint)
        {
            _options = options;
            _proxyStateLookup = proxyStateLookup;
            _connectionLock = new(options.MaxConnectionCount);
            EndPoint = endpoint;

            if (endpoint is not UriTunnelTransportEndPoint)
            {
                throw new NotSupportedException("UriTunnelTransportEndPoint is required.");
                // TODO:throw new NotSupportedException($"UriEndPoint is required for {options.Transport} transport");
            }

            _httpMessageInvoker = new HttpMessageInvoker(
               new SocketsHttpHandler
               {
                   EnableMultipleHttp2Connections = true,
                   PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
                   PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan
               });
        }

        public EndPoint EndPoint { get; }

        private Uri Uri => ((UriTunnelTransportEndPoint)EndPoint).Uri!;

        public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var tunnelId = Uri.Host;
                if (!_proxyStateLookup.TryGetTunnelBackendToFrontend(tunnelId, out var tunnel)) {
                    // TODO: create Validator
                    throw new ArgumentException($"Tunnel {tunnel} not found");
                }
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
                        var connection = await HttpClientConnectionContext.ConnectAsync(_httpMessageInvoker, Uri, cancellationToken);

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
    }
}
