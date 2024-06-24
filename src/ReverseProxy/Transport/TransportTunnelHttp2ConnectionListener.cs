using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This has the core logic that creates and maintains connections to the proxy.
/// </summary>
internal sealed class TransportTunnelHttp2ConnectionListener
    : IConnectionListener
    , IDisposable
{
    private SemaphoreSlim _createHttpMessageInvokerLock;
    private AsyncLockWithOwner _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;
    private CancellationTokenSource _closedCts = new();
    private readonly ILogger _logger;
    private readonly TransportTunnelHttp2Options _options;
    private readonly TunnelState _tunnel;
    private readonly ITransportTunnelHttp2Authentication _transportTunnelHttp2Authentication;
    private readonly UriEndPointHttp2 _endPoint;
    private readonly IncrementalDelay _delay = new();

    private HttpMessageInvoker? _httpMessageInvoker;
    private bool _isDisposed;

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
        if (_isDisposed)
        {
            throw new ObjectDisposedException(nameof(TransportTunnelHttp2ConnectionListener));
        }

        cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

        // Kestrel will keep an active accept call open as long as the transport is active
        using (var connectionLock = await _connectionLock.LockAsync(this, cancellationToken))
        {
            try
            {
                if (_httpMessageInvoker is null)
                {
                    await _createHttpMessageInvokerLock.WaitAsync(cancellationToken);
                    try
                    {
                        _httpMessageInvoker ??= await CreateHttpMessageInvoker();
                    }
                    finally
                    {
                        _createHttpMessageInvokerLock.Release();
                    }
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
                        var (innerConnection, httpContent) = TransportTunnelHttp2ConnectionContext.Create(_logger);
                        requestMessage.Content = httpContent;

                        HttpResponseMessage response;
                        try
                        {
                            response = await _httpMessageInvoker.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception error)
                        {
                            _logger.LogError(error, "httpMessageInvoker.SendAsync {uri}", _endPoint.Uri!);
                            await innerConnection.DisposeAsync();
                            httpContent.Dispose();
                            requestMessage.Dispose();
                            continue;
                        }
                        innerConnection.HttpResponseMessage = response;
                        var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                        innerConnection.Input = PipeReader.Create(responseStream);

                        _delay.Reset();
                        return _connectionCollection.AddInnerConnection(innerConnection, connectionLock);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        requestMessage?.Dispose();
                        _logger.LogWarning(ex, "Connect Async {endpoint}", _endPoint.Uri);
                        // TODO: More sophisticated backoff and retry
                        // Which error needed to be checked? Which error is better or worse?
                        /*
                         * ex.GetType().FullName
                        "System.Net.Http.HttpRequestException"
                        ex.InnerException.GetType().FullName
                        "System.Net.Sockets.SocketException"
                         */

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

        var result = new HttpMessageInvoker(socketsHttpHandler);
        _logger.LogDebug("CreateHttpMessageInvoker {Url}", config.Url);
        return result;
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
        using (var createHttpMessageInvokerLock = _createHttpMessageInvokerLock)
        {
            using (var connectionLock = _connectionLock)
            {
                using (var closedCts = _closedCts)
                {
                    _isDisposed = true;
                    if (disposing)
                    {
                        _createHttpMessageInvokerLock = null!;
                        _connectionLock = null!;
                        _closedCts = null!;
                        _httpMessageInvoker = null;
                    }
                }
            }
        }
    }

    ~TransportTunnelHttp2ConnectionListener()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
