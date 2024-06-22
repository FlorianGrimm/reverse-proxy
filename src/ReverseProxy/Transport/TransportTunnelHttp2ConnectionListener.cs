using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This has the core logic that creates and maintains connections to the proxy.
/// </summary>
internal sealed class TransportTunnelHttp2ConnectionListener : IConnectionListener
{
    private readonly SemaphoreSlim _createHttpMessageInvokerLock;
    private readonly SemaphoreSlim _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;
    private readonly CancellationTokenSource _closedCts = new();
    private readonly ILogger _logger;
    private readonly TransportTunnelHttp2Options _options;
    private readonly TunnelState _tunnel;
    private readonly ITransportTunnelHttp2Authentication _transportTunnelHttp2Authentication;
    private readonly UriEndPointHttp2 _endPoint;
    private readonly IncrementalDelay _delay = new();

    private HttpMessageInvoker? _httpMessageInvoker;

    public TransportTunnelHttp2ConnectionListener(
        UriEndPointHttp2 endpoint,
        TunnelState tunnel,
        ITransportTunnelHttp2Authentication transportTunnelHttp2Authentication,
        TransportTunnelHttp2Options options,
        ILogger logger
        )
    {
        if (string.IsNullOrEmpty(endpoint.Uri?.ToString()))
        {
            throw new ArgumentException("UriEndPoint.Uri is required", nameof(endpoint));
        }
        _createHttpMessageInvokerLock = new(1, 1);
        _connectionLock = new(options.MaxConnectionCount);
        _connectionCollection = new TrackLifetimeConnectionContextCollection(_connections, _connectionLock);
        _logger = logger;
        _options = options;
        _tunnel = tunnel;
        _transportTunnelHttp2Authentication = transportTunnelHttp2Authentication;
        _endPoint = endpoint;
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
                await _createHttpMessageInvokerLock.WaitAsync(cancellationToken);
                _httpMessageInvoker ??= await CreateHttpMessageInvoker();
                _createHttpMessageInvokerLock.Release();
            }

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var requestMessage = new HttpRequestMessage(
                    HttpMethod.Post, _endPoint.Uri!)
                {
                    Version = new Version(2, 0)
                };

                // configure the 
                {
                    var config = _tunnel.Model.Config;
                    await _transportTunnelHttp2Authentication.ConfigureHttpRequestMessageAsync(config, requestMessage);
                    if (_options.ConfigureHttpRequestMessageAsync is { } configure)
                    {
                        await configure(config, requestMessage);
                    }
                }

                try
                {
                    var innerConnection = await TransportTunnelHttp2ConnectionContext.ConnectAsync(
                        requestMessage, _httpMessageInvoker, cancellationToken);
                    _delay.Reset();
                    return _connectionCollection.AddInnerConnection(innerConnection);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    requestMessage?.Dispose();
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

    private async Task<HttpMessageInvoker> CreateHttpMessageInvoker()
    {
        var socketsHttpHandler = new SocketsHttpHandler
        {
            EnableMultipleHttp2Connections = true,
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
        };

        // set the socketsHttpHandler.SslOptions based on the tunnel configuration authentication
        var config = _tunnel.Model.Config;

        if (config.Authentication.ClientCertifiacteCollection is { } certificates)
        {
            var clientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= new();
            clientCertificates.AddRange(certificates);
        }

        await _transportTunnelHttp2Authentication.ConfigureSocketsHttpHandlerAsync(config, socketsHttpHandler);

        // allow the user to configure the handler
        if (_options.ConfigureSocketsHttpHandlerAsync is { } configure)
        {
            await configure(config, socketsHttpHandler);
        }

        return new HttpMessageInvoker(socketsHttpHandler);
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
