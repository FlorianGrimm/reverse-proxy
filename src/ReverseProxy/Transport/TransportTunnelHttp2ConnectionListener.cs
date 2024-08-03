// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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

        var config = _tunnel.Model.Config;

        // Kestrel will keep an active accept call open as long as the transport is active
        using (var currentConnectionlock = await _connectionLock.LockAsync(this, cancellationToken))
        {
            try
            {
                while (true)
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
                            _ = _createHttpMessageInvokerLock.Release();
                        }
                    }


                    TransportTunnelHttp2ConnectionContext? innerConnection = null;
                    HttpContent? httpContent = null;
                    HttpResponseMessage? response = null;
                    var requestMessage = new HttpRequestMessage(
                            HttpMethod.Post, _endPoint.Uri!)
                    {
                        Version = new Version(2, 0)
                    };

                    try
                    {

                        if (cancellationToken.IsCancellationRequested || _isDisposed)
                        {
                            return null;
                        }

                        {
                            await _transportTunnelHttp2Authentication.ConfigureHttpRequestMessageAsync(_tunnel, requestMessage);
                            if (_options.ConfigureHttpRequestMessageAsync is { } configure)
                            {
                                await configure(config, requestMessage);
                            }
                        }


                        (innerConnection, httpContent) = TransportTunnelHttp2ConnectionContext.Create(_logger);
                        requestMessage.Content = httpContent;
                        response = await _httpMessageInvoker.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);
                        response.EnsureSuccessStatusCode();
                        innerConnection.HttpResponseMessage = response;
                        var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                        innerConnection.Input = PipeReader.Create(responseStream);
                        var result = _connectionCollection.AddInnerConnection(innerConnection, currentConnectionlock);

                        if (_delay.Reset())
                        {
                            Log.TunnelResumeConnectTunnel(_logger, config.TunnelId, config.Url, config.Transport, null);
                        }

                        return result;
                    }
                    catch (Exception error)
                    {
                        _logger.LogWarning(error, "Failed to connect to tunnel '{TunnelId}' at '{RemoteUrl}' {Transport}.", config.TunnelId, config.Url, config.Transport);
                        if (requestMessage is not null) { requestMessage.Dispose(); }
                        if (innerConnection is not null) { await innerConnection.DisposeAsync(); }
                        if (httpContent is not null) { httpContent.Dispose(); }

                        if (error is OperationCanceledException) { return null; }

                        // TODO: More sophisticated backoff and retry
                        // Which error needed to be checked? Which error is better or worse?
                        var raiseWarning = _delay.IncrementDelay();
                        if (raiseWarning)
                        {
                            Log.TunnelCannotConnectTunnel(_logger, config.TunnelId, config.Url, config.Transport, error);
                        }
                        await _delay.Delay(cancellationToken);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (Exception error)
            {
                Log.AcceptFailed(_logger, config.Url, error);
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

        var config = _tunnel.Model.Config;

        var result = await _transportTunnelHttp2Authentication.ConfigureSocketsHttpHandlerAsync(_tunnel, socketsHttpHandler);

        // allow the user to configure the handler
        if (_options.ConfigureSocketsHttpHandlerAsync is { } configureSocketsHttpHandlerAsync)
        {
            await configureSocketsHttpHandlerAsync(config, socketsHttpHandler, _transportTunnelHttp2Authentication);
        }

        if (result is null)
        {
            result = new HttpMessageInvoker(socketsHttpHandler);
        }
        Log.TunnelCreateHttpMessageInvoker(_logger, config.TunnelId, config.Url);
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

        System.GC.SuppressFinalize(this);
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

    private static class Log
    {
        private static readonly Action<ILogger, string, string, Exception?> _tunnelCreateHttpMessageInvoker = LoggerMessage.Define<string, string>(
            LogLevel.Debug,
            EventIds.TunnelCreateHttpMessageInvoker,
            "Tunnel '{TunnelId}' create HttpMessageInvoker for '{RemoteUrl}'.");

        public static void TunnelCreateHttpMessageInvoker(ILogger logger, string tunnelId, string url)
        {
            _tunnelCreateHttpMessageInvoker(logger, tunnelId, url, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _tunnelCannotConnectTunnel = LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            EventIds.TunnelCannotConnectTunnel,
            "Tunnel '{TunnelId}' cannot connect to '{RemoteUrl}' {Transport}.");

        internal static void TunnelCannotConnectTunnel(ILogger logger, string tunnelId, string url, string transport, Exception? error)
        {
            _tunnelCannotConnectTunnel(logger, tunnelId, url, transport, error);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _tunnelResumeConnectTunnel = LoggerMessage.Define<string, string, string>(
            LogLevel.Warning,
            EventIds.TunnelResumeConnectTunnel,
            "Tunnel '{TunnelId}' cannot connect to '{RemoteUrl}' {Transport}.");

        internal static void TunnelResumeConnectTunnel(ILogger logger, string tunnelId, string url, string transport, Exception? error)
        {
            _tunnelResumeConnectTunnel(logger, tunnelId, url, transport, error);
        }

        private static readonly Action<ILogger, string, Exception?> _acceptFailed = LoggerMessage.Define<string>(
            LogLevel.Information,
            EventIds.TransportHttp2AcceptFailed,
            "Transport Http2 Accept failed: {endpoint}.");

        public static void AcceptFailed(ILogger logger, string url, Exception? error)
        {
            _acceptFailed(logger, url, error);
        }
        /*
        private static readonly Action<ILogger, string, string, Exception?> _x = LoggerMessage.Define<string, string>(
            LogLevel.Debug,
            EventIds.TunnelCreateHttpMessageInvoker,
            "Tunnel '{TunnelId}' create HttpMessageInvoker for '{RemoteUrl}'.");

        public static void X(ILogger logger, string tunnelId, string url)
        {
            _x(logger, tunnelId, url, null);
        }
        */
    }
}
