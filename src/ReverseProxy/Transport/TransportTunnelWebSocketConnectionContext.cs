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
    private WebSocket? _underlyingWebSocket;
    private TrackLifetimeConnectionContextCollection? _trackLifetimeConnectionContextCollection;

    private TransportTunnelWebSocketConnectionContext(HttpConnectionOptions options)
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
        _underlyingWebSocket?.Abort();
        _trackLifetimeConnectionContextCollection?.Remove(this);
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        _cts.Cancel();
        _underlyingWebSocket?.Abort();
        _trackLifetimeConnectionContextCollection?.Remove(this);
    }

    public override ValueTask DisposeAsync()
    {
        // REVIEW: Why doesn't dispose just work?
        Abort();

        return base.DisposeAsync();
    }

    internal static async ValueTask<TransportTunnelWebSocketConnectionContext> ConnectAsync(
        Uri uri,
        Action<ClientWebSocket> configureClientWebSocket,
        CancellationToken cancellationToken)
    {
        ClientWebSocket? underlyingWebSocket = null;
        var options = new HttpConnectionOptions
        {
            Url = uri,
            Transports = HttpTransportType.WebSockets,
            SkipNegotiation = true,
            WebSocketFactory = async (context, cancellationToken) => {
                underlyingWebSocket = new ClientWebSocket();
                underlyingWebSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(5);

                // underlyingWebSocket.Options.ClientCertificates

                if (configureClientWebSocket is not null)
                {
                    configureClientWebSocket(underlyingWebSocket);
                }
                await underlyingWebSocket.ConnectAsync(context.Uri, cancellationToken);
                return underlyingWebSocket;
            }
        };

        var connection = new TransportTunnelWebSocketConnectionContext(options);
        await connection.StartAsync(TransferFormat.Binary, cancellationToken);
        connection._underlyingWebSocket = underlyingWebSocket;
        return connection;
    }

}
