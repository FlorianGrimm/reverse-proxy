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
    private readonly ITransportTunnelHttp2Authenticator _authenticator;
    private readonly UriEndPointHttp2 _endPoint;
    private readonly IncrementalDelay _delay = new();

    private HttpMessageInvoker? _httpMessageInvoker;
    private bool _isDisposed;

    public TransportTunnelHttp2ConnectionListener(
        UriEndPointHttp2 endpoint,
        TunnelState tunnel,
        ITransportTunnelHttp2Authenticator authenticator,
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
        _connectionCollection = new TrackLifetimeConnectionContextCollection(_connections);
        _logger = logger;
        _options = options;
        _tunnel = tunnel;
        _authenticator = authenticator;
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
        using (var currentConnectionLock = await _connectionLock.LockAsync(this, cancellationToken))
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

                    TransportTunnelHttp2ConnectionContext? connectionContext = null;
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
                            await _authenticator.ConfigureHttpRequestMessageAsync(_tunnel, requestMessage);
                            if (_options.ConfigureHttpRequestMessageAsync is { } configure)
                            {
                                await configure(config, requestMessage);
                            }
                        }
                        (connectionContext, httpContent) = TransportTunnelHttp2ConnectionContext.Create(_logger);
                        if (Log.IsTransportSendTransportTunnelEnabled(_logger))
                        {
                            Log.TransportSendTransportTunnel(_logger, _tunnel.TunnelId, requestMessage.Method, requestMessage.RequestUri, requestMessage.Content?.Headers.ContentLength);
                        }
                        requestMessage.Content = httpContent;
                        response = await _httpMessageInvoker.SendAsync(requestMessage, cancellationToken).ConfigureAwait(false);
                        response.EnsureSuccessStatusCode();
                        connectionContext.HttpResponseMessage = response;
                        var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                        connectionContext.Input = PipeReader.Create(responseStream);
                        _connectionCollection.AddInnerConnection(connectionContext, currentConnectionLock);

                        if (_delay.Reset())
                        {
                            Log.TunnelResumeConnectTunnel(_logger, config.TunnelId, config.Url, config.Transport, null);
                        }
                        return connectionContext;
                    }
                    catch (Exception error)
                    {
                        Log.TransportFailureSendTransportTunnel(_logger, config.TunnelId, config.Url, config.Transport);
                        if (requestMessage is not null) { requestMessage.Dispose(); }
                        if (connectionContext is not null) { await connectionContext.DisposeAsync(); }
                        if (httpContent is not null) { httpContent.Dispose(); }

                        if (error is OperationCanceledException) { return null; }

                        // TODO: More sophisticated back off and retry
                        Log.TunnelCannotConnectTunnel(_logger, config.TunnelId, config.Url, config.Transport, error);
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
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = Timeout.InfiniteTimeSpan,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
        };

        var config = _tunnel.Model.Config;

        var result = await _authenticator.ConfigureSocketsHttpHandlerAsync(_tunnel, socketsHttpHandler);

        // allow the user to configure the handler
        if (_options.ConfigureSocketsHttpHandlerAsync is { } configureSocketsHttpHandlerAsync)
        {
            await configureSocketsHttpHandlerAsync(config, socketsHttpHandler, _authenticator);
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

        private static readonly Action<ILogger, string, HttpMethod, string?, long?, Exception?> _transportSendTransportTunnel = LoggerMessage.Define<string, HttpMethod, string?, long?>(
            LogLevel.Debug,
            EventIds.TransportSendTransportTunnel,
            "Send Transport Tunnel '{TunnelId}' {Method} {RequestUri} {ContentLength}.");

        public static bool IsTransportSendTransportTunnelEnabled(ILogger logger) => logger.IsEnabled(LogLevel.Debug);

        public static void TransportSendTransportTunnel(ILogger logger, string tunnelId, HttpMethod method, Uri? requestUri, long? contentLength)
        {
            _transportSendTransportTunnel(logger, tunnelId, method, requestUri?.ToString(), contentLength, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _transportFailureSendTransportTunnel = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.TunnelCreateHttpMessageInvoker,
            "Failed to connect to tunnel '{TunnelId}' at '{RemoteUrl}' {Transport}.");

        public static void TransportFailureSendTransportTunnel(ILogger logger, string tunnelId, string url, string transport)
        {
            _transportFailureSendTransportTunnel(logger, tunnelId, url, transport, null);
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
