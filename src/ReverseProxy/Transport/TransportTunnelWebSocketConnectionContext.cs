using System;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Connections.Client;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketConnectionContext
    : HttpConnection
    , ITrackLifetimeConnectionContext
{
    private readonly CancellationTokenSource _cts = new();
    internal WebSocket? underlyingWebSocket;
    private TrackLifetimeConnectionContextCollection? _trackLifetimeConnectionContextCollection;

    internal TransportTunnelWebSocketConnectionContext(HttpConnectionOptions options)
        : base(options, null)
    {
    }

    public override CancellationToken ConnectionClosed
    {
        get => _cts.Token;
        set { }
    }


    public void SetTracklifetime(TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection)
    {
        _trackLifetimeConnectionContextCollection = trackLifetimeConnectionContextCollection;
    }

    public override void Abort()
    {
        _cts.Cancel();
        underlyingWebSocket?.Abort();
        _trackLifetimeConnectionContextCollection?.Remove(this);
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        _cts.Cancel();
        underlyingWebSocket?.Abort();
        _trackLifetimeConnectionContextCollection?.Remove(this);
    }

    public override ValueTask DisposeAsync()
    {
        // REVIEW: Why doesn't dispose just work?
        Abort();

        return base.DisposeAsync();
    }
}
