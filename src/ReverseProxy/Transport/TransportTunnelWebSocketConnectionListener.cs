using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This has the core logic that creates and maintains connections to the proxy.
/// </summary>
internal sealed class TransportTunnelWebSocketConnectionListener : IConnectionListener
{
    private readonly SemaphoreSlim _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TransportTunnelWebSocketOptions _options;
    private readonly ILogger _logger;
    private readonly TunnelState _tunnel;
    private readonly CancellationTokenSource _closedCts = new();
    private readonly UriWebSocketEndPoint _endPoint;
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;
    private readonly IncrementalDelay _delay = new();

    public TransportTunnelWebSocketConnectionListener(
        UriWebSocketEndPoint endpoint,
        TunnelState tunnel,
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
        _options = options;
        _logger = logger;
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

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var innerConnection = await TransportTunnelWebSocketConnectionContext.ConnectAsync(
                        _endPoint.Uri!, onConfigureClientWebSocket, cancellationToken);
                    _delay.Reset();
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
                    await _delay.Delay(cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private void onConfigureClientWebSocket(ClientWebSocket socket)
    {

#warning TODO: add caching of the certificate
#warning TODO: TEST

        // set the socketsHttpHandler.SslOptions based on the tunnel configuration authentication
        var config = _tunnel.Model.Config;
#warning TODO config.Authentication.ClientCertificate
        //if (config.Authentication.ClientCertificate is { Length: > 0 } certificateName)
        //{
        //    if (!(_optionalCertificateStore.GetService() is { } certificateStore))
        //    {
        //        throw new InvalidOperationException("No CertificateStore");
        //    }

        //    var certificate = certificateStore.GetCertificate(certificateName);
        //    if (certificate is null)
        //    {
        //        throw new InvalidOperationException("No Certificate");
        //    }

        //    var clientCertificates = socket.Options.ClientCertificates ??= new();
        //    clientCertificates.Add(certificate);
        //}

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
}
