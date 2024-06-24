using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This has the core logic that creates and maintains connections to the proxy.
/// </summary>
internal sealed class TransportTunnelWebSocketConnectionListener
    : IConnectionListener
    , IDisposable
{
    private CancellationTokenSource _closedCts = new();
    private SemaphoreSlim _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TransportTunnelWebSocketOptions _options;
    private readonly ILogger _logger;
    private readonly TunnelState _tunnel;
    private readonly ITransportTunnelWebSocketAuthentication _transportTunnelWebSocketAuthentication;
    private readonly UriWebSocketEndPoint _endPoint;
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;
    private readonly IncrementalDelay _delay = new();
    private bool _isDisposed;

    public TransportTunnelWebSocketConnectionListener(
        UriWebSocketEndPoint endpoint,
        TunnelState tunnel,
        ITransportTunnelWebSocketAuthentication transportTunnelWebSocketAuthentication,
        TransportTunnelWebSocketOptions options,
        ILogger logger
        )
    {
        if (endpoint.Uri is null)
        {
            throw new ArgumentException("UriEndPoint.Uri is required", nameof(endpoint));
        }
        _endPoint = endpoint;
        _tunnel = tunnel;
        _transportTunnelWebSocketAuthentication = transportTunnelWebSocketAuthentication;
        _options = options;
        _logger = logger;
        _connectionLock = new(options.MaxConnectionCount);
        _connectionCollection = new TrackLifetimeConnectionContextCollection(_connections, _connectionLock);
    }

    public EndPoint EndPoint => _endPoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

        // Kestrel will keep an active accept call open as long as the transport is active
        await _connectionLock.WaitAsync(cancellationToken);

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var uri = _endPoint.Uri!;
                    ClientWebSocket? underlyingWebSocket = null;
                    var options = new HttpConnectionOptions
                    {
                        Url = uri,
                        Transports = HttpTransportType.WebSockets,
                        SkipNegotiation = true,
                        WebSocketFactory = async (context, cancellationToken) =>
                        {
                            underlyingWebSocket = new ClientWebSocket();
                            underlyingWebSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(5);

                            await onConfigureClientWebSocket(underlyingWebSocket);
                            try
                            {
                                await underlyingWebSocket.ConnectAsync(context.Uri, cancellationToken);
                            }
                            catch (Exception error)
                            {
                                _logger.LogError(error, "ConnectAsync {uri}", context.Uri);
                                throw;
                            }
                            _logger.LogDebug("Created WebSocket {uri}", context.Uri);
                            return underlyingWebSocket;
                        }
                    };

                    var innerConnection = new TransportTunnelWebSocketConnectionContext(options);
                    await innerConnection.StartAsync(TransferFormat.Binary, cancellationToken);
                    innerConnection.underlyingWebSocket = underlyingWebSocket;

                    _delay.Reset();

                    // _connectionLock.Release() is done in the TrackLifetimeConnectionContextCollection
                    return _connectionCollection.AddInnerConnection(innerConnection);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    _logger.LogError(error, "Connect Async {endpoint}", _endPoint.Uri);
                    // TODO: More sophisticated backoff and retry
                    await _delay.Delay(cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            _connectionLock.Release();
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AcceptAsync {endpoint}", _endPoint.Uri);
            _connectionLock.Release();
            throw;
        }
    }

    private async ValueTask<TransportTunnelWebSocketConnectionContext> ConnectAsync(CancellationToken cancellationToken)
    {
        var uri = _endPoint.Uri!;
        ClientWebSocket? underlyingWebSocket = null;
        var options = new HttpConnectionOptions
        {
            Url = uri,
            Transports = HttpTransportType.WebSockets,
            SkipNegotiation = true,
            WebSocketFactory = async (context, cancellationToken) =>
            {
                underlyingWebSocket = new ClientWebSocket();
                underlyingWebSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(5);

                await onConfigureClientWebSocket(underlyingWebSocket);
                try
                {
                    await underlyingWebSocket.ConnectAsync(context.Uri, cancellationToken);
                }
                catch (Exception error)
                {
                    _logger.LogError(error, "ConnectAsync {uri}", context.Uri);
                    throw;
                }
                _logger.LogDebug("Created WebSocket {uri}", context.Uri);
                return underlyingWebSocket;
            }
        };

        var connection = new TransportTunnelWebSocketConnectionContext(options);
        await connection.StartAsync(TransferFormat.Binary, cancellationToken);
        connection.underlyingWebSocket = underlyingWebSocket;
        return connection;
    }

    private async ValueTask onConfigureClientWebSocket(ClientWebSocket socket)
    {
        // set the socketsHttpHandler.SslOptions based on the tunnel configuration authentication
        var config = _tunnel.Model.Config;

        await _transportTunnelWebSocketAuthentication.ConfigureClientWebSocketAsync(config, socket);

        if (config.Authentication.ClientCertifiacteCollection is { } certificates)
        {
            var clientCertificates = socket.Options.ClientCertificates ??= new();
            clientCertificates.AddRange(certificates);
        }

        if (_options.ConfigureClientWebSocket is { } configureClientWebSocket)
        {
            configureClientWebSocket(_tunnel.Model.Config, socket);
        }
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

    private void Dispose(bool disposing)
    {
        using (var closedCts = _closedCts) {
            using (var connectionLock = _connectionLock) {
            _isDisposed = true;
            if (disposing) {
                _closedCts = null!;
                    _connectionLock = null!;
            }
            }
        }
            if (!_isDisposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                _isDisposed = true;
            }
    }

    ~TransportTunnelWebSocketConnectionListener()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
