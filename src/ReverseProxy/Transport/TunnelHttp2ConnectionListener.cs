using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This has the core logic that creates and maintains connections to the proxy.
/// </summary>
internal sealed class TunnelHttp2ConnectionListener : IConnectionListener
{
    private readonly SemaphoreSlim _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TunnelHttp2Options _options;
    private readonly CancellationTokenSource _closedCts = new();
    private readonly UriEndPointHttp2 _endPoint;
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;

    private HttpMessageInvoker? _httpMessageInvoker;

    public TunnelHttp2ConnectionListener(TunnelHttp2Options options, UriEndPointHttp2 endpoint)
    {
        if (string.IsNullOrEmpty(endpoint.Uri?.ToString()))
        {
            throw new ArgumentException("UriEndPoint.Uri is required", nameof(endpoint));
        }
        _options = options;
        _endPoint = endpoint;
        _connectionLock = new(options.MaxConnectionCount);
        _connectionCollection = new TrackLifetimeConnectionContextCollection(_connections, _connectionLock);
    }

    public EndPoint EndPoint => _endPoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

            // Kestrel will keep an active accept call open as long as the transport is active
            await _connectionLock.WaitAsync(cancellationToken);
            if (_httpMessageInvoker is null)
            {
                lock (this)
                {
                    _httpMessageInvoker ??= CreateHttpMessageInvoker();
                }
            }

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int delay = 0;
                try
                {
                    var innerConnection = await HttpClientConnectionContext.ConnectAsync(
                        _httpMessageInvoker, _endPoint.Uri!, cancellationToken);
                    delay = 0;
                    return _connectionCollection.AddInnerConnection(innerConnection);
#if WEICHEI
                    var connection = new TrackLifetimeConnectionContext(innerConnection);

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
#endif

                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // TODO: More sophisticated backoff and retry
                    if (delay < 60000)
                    {
                        delay += 5000;
                    }
                    await Task.Delay(delay, cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private HttpMessageInvoker CreateHttpMessageInvoker()
    {
        var socketsHttpHandler = new SocketsHttpHandler
        {
            EnableMultipleHttp2Connections = true,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan
        };
        if (_options.ConfigureSocketsHttpHandler is { } configure)
        {
            configure(_endPoint.Uri!, socketsHttpHandler);
        }
        return _httpMessageInvoker = new HttpMessageInvoker(socketsHttpHandler);
    }

    public async ValueTask DisposeAsync()
    {
        var listConnections = _connections.Values.ToList();
        List<Task> tasks = new(listConnections.Count);
        foreach (var connection in listConnections)
        {
            tasks.Add(connection.DisposeAsync().AsTask());
        }

        if (tasks.Count > 0)
        {
            await Task.WhenAll(tasks);
        }
    }

    public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        _closedCts.Cancel();

        var listConnections = _connections.Values.ToList();
        foreach (var connection in listConnections)
        {
            // REVIEW: Graceful?
            connection.Abort();
        }

        return ValueTask.CompletedTask;
    }
}
