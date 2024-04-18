using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel.Transport;

internal class TunnelConnectionListenerWebSocket : TunnelConnectionListenerProtocol
{
    public TunnelConnectionListenerWebSocket(
        UriTunnelTransportEndPoint uriTunnelTransportEndPoint,
        string tunnelId,
        TunnelBackendToFrontendState backendToFrontend,
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        TunnelBackendOptions options,
        ILogger<TunnelConnectionListenerWebSocket> logger)
        : base(uriTunnelTransportEndPoint, tunnelId, backendToFrontend, proxyTunnelConfigManager, options, logger)
    {
    }
    public override async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var tunnelId = _backendToFrontend.TunnelId;
            if (!_proxyTunnelConfigManager.TryGetTunnelBackendToFrontend(tunnelId, out var tunnel))
            {
                // TODO: create Validator
                throw new ArgumentException($"Tunnel {tunnel} not found");
            }
            
            var uri = GetRemoteUrl(tunnel);
            
            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

            // Kestrel will keep an active accept call open as long as the transport is active
            await _connectionLock.WaitAsync(cancellationToken);

            Log.TunnelConnectionListenerAccept(_logger, tunnelId, _backendToFrontend.Transport, uri.ToString());

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    /*
                    var connection = new TrackLifetimeConnectionContext(_options.Transport switch
                    {
                        TransportType.WebSockets => await WebSocketConnectionContext.ConnectAsync(Uri, cancellationToken),
                        TransportType.HTTP2 => await HttpClientConnectionContext.ConnectAsync(_httpMessageInvoker, Uri, cancellationToken),
                        _ => throw new NotSupportedException(),
                    });
                    */
                    var connection = await TunnelConnectionContextWebSocket.ConnectAsync(uri, cancellationToken);

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
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // TODO: More sophisticated backoff and retry
                    await Task.Delay(5000, cancellationToken);
                }
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }
    protected override Uri GetRemoteUrl(TunnelBackendToFrontendState tunnel)
    {
        var url = tunnel.Url;
        var remoteTunnelId = tunnel.RemoteTunnelId;
        var host = tunnel.TunnelId; // TODO: host needs a configuration
        var uri = new Uri(new Uri(url), $"/Tunnel/WebSocket/{remoteTunnelId}/{host}");
        return uri;
    }

    protected override Task<TrackLifetimeConnectionContext> ConnectAsync(HttpMessageInvoker httpMessageInvoker, Uri uri, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
// public class TunnelConnectionListenerWebTransport: TunnelConnectionListenerProtocol { }
