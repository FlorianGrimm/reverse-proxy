// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CA1513 // ObjectDisposedException.ThrowIf does not exist in dotnet 6.0

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
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
using Yarp.ReverseProxy.Tunnel;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelLoopbackConnectionListener
    : IConnectionListener
    , IDisposable
{
    private SemaphoreSlim _createHttpMessageInvokerLock;
    private AsyncLockWithOwner _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections = new();
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;
    private CancellationTokenSource _closedCts = new();
    private readonly ILogger _logger;
    private readonly TransportTunnelLoopbackOptions _options;
    private readonly TunnelState _tunnel;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ITransportTunnelLoopbackAuthenticator _authenticator;
    private readonly LoopbackEndPoint _endPoint;
    private readonly IncrementalDelay _delay = new();

    private bool _isDisposed;

    public TransportTunnelLoopbackConnectionListener(
        LoopbackEndPoint endpoint,
        TunnelState tunnel,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ITransportTunnelLoopbackAuthenticator authenticator,
        TransportTunnelLoopbackOptions options,
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
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _authenticator = authenticator;
        _endPoint = endpoint;
    }

    public EndPoint EndPoint => _endPoint;

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        if (_isDisposed)
        {
            throw new ObjectDisposedException(nameof(TransportTunnelLoopbackConnectionListener));
        }

        cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

        var config = _tunnel.Model.Config;
        var remoteTunnelId = config.GetRemoteTunnelId();
        if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(remoteTunnelId, out var channels))
        {
            throw new Exception($"remoteTunnelId:{remoteTunnelId}; not found.");
        }
        _logger.LogInformation("Adding loopback Tunnel {remoteTunnelId}", remoteTunnelId);

        // Kestrel will keep an active accept call open as long as the transport is active
        using (var currentConnectionLock = await _connectionLock.LockAsync(this, cancellationToken))
        {
            try
            {
                while (true)
                {
                    var channelsReader = channels.Reader;
                    TunnelConnectionRequest? tunnelConnectionStream = null;
                    while (!channelsReader.TryRead(out tunnelConnectionStream) || tunnelConnectionStream is null)
                    {
                        await channelsReader.WaitToReadAsync(cancellationToken);
                    }

                    var (connectionContext, streamClient) = TransportTunnelLoopbackConnectionContext.Create(_logger);
                    tunnelConnectionStream.SetStream(streamClient);

                    _connectionCollection.AddInnerConnection(connectionContext, currentConnectionLock);

                    if (_delay.Reset())
                    {
                        Log.TunnelResumeConnectTunnel(_logger, config.TunnelId, config.Url, config.Transport, null);
                    }
                    return connectionContext;
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

#if NET8_0_OR_GREATER
    public async ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        await _closedCts.CancelAsync();

        var listConnections = _connections.Values.ToList();
        foreach (var connection in listConnections)
        {
            // REVIEW: Graceful?
            connection.Abort();
        }
    }
#else
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
#endif

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
                    }
                }
            }
        }
    }

    ~TransportTunnelLoopbackConnectionListener()
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
