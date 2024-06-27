// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This has the core logic that creates and maintains connections to the proxy.
/// </summary>
internal sealed class TransportTunnelWebSocketConnectionListener
    : IConnectionListener
    , IDisposable
{
    private CancellationTokenSource _closedCts = new();
    private AsyncLockWithOwner _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TransportTunnelWebSocketOptions _options;
    private readonly ILoggerFactory? _loggerFactory;
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
        ILoggerFactory? loggerFactory,
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
        _loggerFactory = loggerFactory;
        _logger = logger;
        _connectionLock = new(options.MaxConnectionCount);
        _connectionCollection = new TrackLifetimeConnectionContextCollection(_connections, _connectionLock);
    }

    public EndPoint EndPoint => _endPoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

        // Kestrel will keep an active accept call open as long as the transport is active
        using (var connectionLock = await _connectionLock.LockAsync(this, cancellationToken))
        {
            try
            {
                while (true)
                {
                    if (cancellationToken.IsCancellationRequested || _isDisposed)
                    {
                        return null;
                    }

                    var config = _tunnel.Model.Config;

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
                                catch (Exception error) when (error is not OperationCanceledException)
                                {
                                    Log.AcceptFailed(_logger, context.Uri, error);
                                    throw;
                                }
                                return underlyingWebSocket;
                            }
                        };

                        var innerConnection = new TransportTunnelWebSocketConnectionContext(options, _logger, _loggerFactory);
                        await innerConnection.StartAsync(TransferFormat.Binary, cancellationToken);
                        innerConnection.underlyingWebSocket = underlyingWebSocket;

                        if (_delay.Reset())
                        {
                            Log.TunnelResumeConnectTunnel(_logger, config.TunnelId, config.Url, config.Transport, null);
                        }

                        return _connectionCollection.AddInnerConnection(innerConnection, connectionLock);
                    }
                    catch (Exception error) when (error is not OperationCanceledException)
                    {
                        // TODO: More sophisticated backoff and retry
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
                Log.AcceptFailed(_logger, _endPoint.Uri!, error);
                throw;
            }
        }
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
        using (var closedCts = _closedCts)
        {
            using (var connectionLock = _connectionLock)
            {
                _isDisposed = true;
                if (disposing)
                {
                    _closedCts = null!;
                    _connectionLock = null!;
                }
            }
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

        private static readonly Action<ILogger, string, string, TransportMode, Exception?> _tunnelCannotConnectTunnel = LoggerMessage.Define<string, string, TransportMode>(
            LogLevel.Error,
            EventIds.TunnelCannotConnectTunnel,
            "Tunnel '{TunnelId}' cannot connect to '{RemoteUrl}' {Transport}.");

        internal static void TunnelCannotConnectTunnel(ILogger logger, string tunnelId, string url, TransportMode transport, Exception? error)
        {
            _tunnelCannotConnectTunnel(logger, tunnelId, url, transport, error);
        }

        private static readonly Action<ILogger, string, string, TransportMode, Exception?> _tunnelResumeConnectTunnel = LoggerMessage.Define<string, string, TransportMode>(
            LogLevel.Warning,
            EventIds.TunnelResumeConnectTunnel,
            "Tunnel '{TunnelId}' (resumed) connect to '{RemoteUrl}' {Transport}.");

        internal static void TunnelResumeConnectTunnel(ILogger logger, string tunnelId, string url, TransportMode transport, Exception? error)
        {
            _tunnelResumeConnectTunnel(logger, tunnelId, url, transport, error);
        }

        private static readonly Action<ILogger, Uri, Exception?> _AcceptFailed = LoggerMessage.Define<Uri>(
            LogLevel.Information,
            EventIds.TransportWebSocketAcceptFailed,
            "Transport WebSocket Accept failed: {endpoint}.");

        public static void AcceptFailed(ILogger logger, Uri url, Exception? error)
        {
            _AcceptFailed(logger, url, error);
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
