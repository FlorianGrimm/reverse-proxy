// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketConnectionContext
    : HttpConnection
    , ITrackLifetimeConnectionContext
{
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger _logger;
    internal WebSocket? underlyingWebSocket;
    private TrackLifetimeConnectionContextCollection? _trackLifetimeConnectionContextCollection;
    private AsyncLockOwner _asyncLockOwner;

    internal TransportTunnelWebSocketConnectionContext(
        HttpConnectionOptions options,
        ILogger logger,
        ILoggerFactory? loggerFactory)
        : base(options, loggerFactory)
    {
        _logger = logger;
    }

    public override CancellationToken ConnectionClosed
    {
        get => _cts.Token;
        set { }
    }

    public void SetTracklifetime(
        TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection,
        AsyncLockOwner asyncLockOwner)
    {
        _trackLifetimeConnectionContextCollection = trackLifetimeConnectionContextCollection;
        _asyncLockOwner = asyncLockOwner;
    }

    public override void Abort()
    {
        _cts.Cancel();
        underlyingWebSocket?.Abort();
        var releasedLock = _asyncLockOwner.Release();
        var removedFromCollection = _trackLifetimeConnectionContextCollection?.TryRemove(this) ?? false;
        /*
        if (releasedLock != removedFromCollection)
        {
            // time for investigation??
            _logger.LogInformation("Mismatched lock release and collection removal releasedLock:{releasedLock} removedFromCollection:{removedFromCollection}", releasedLock, removedFromCollection);
        }
        */
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        _cts.Cancel();
        underlyingWebSocket?.Abort();
        var removedFromCollection = _trackLifetimeConnectionContextCollection?.TryRemove(this) ?? false;
        var releasedLock = _asyncLockOwner.Release();
        /*
        if (releasedLock != removedFromCollection)
        {
            _logger.LogInformation("Mismatched lock release and collection removal releasedLock:{releasedLock} removedFromCollection:{removedFromCollection}", releasedLock, removedFromCollection);
        }
        else
        {
            _logger.LogInformation("Matched lock release and collection removal releasedLock:{releasedLock} removedFromCollection:{removedFromCollection}", releasedLock, removedFromCollection);
        }
        */
    }

    public override ValueTask DisposeAsync()
    {
        Abort();

        return base.DisposeAsync();
    }
}
