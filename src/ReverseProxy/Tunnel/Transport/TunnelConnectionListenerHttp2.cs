using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel.Transport;

internal class TunnelConnectionListenerHttp2 : TunnelConnectionListenerProtocol
{
    public TunnelConnectionListenerHttp2(
        UriTunnelTransportEndPoint uriTunnelTransportEndPoint,
        string tunnelId,
        TunnelBackendToFrontendState backendToFrontend,
        IProxyTunnelStateLookup proxyTunnelConfigManager,
        TunnelBackendOptions options)
        : base(uriTunnelTransportEndPoint, tunnelId, backendToFrontend, proxyTunnelConfigManager, options)
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

            var url = tunnel.Url;
            var remoteTunnelId = tunnel.RemoteTunnelId;
            var host = tunnelId; // TODO: host needs a configuration
            var uri = new Uri(new Uri(url), $"/Tunnel/HTTP2/{remoteTunnelId}/{host}");


            cancellationToken = CancellationTokenSource.CreateLinkedTokenSource(_closedCts.Token, cancellationToken).Token;

            // Kestrel will keep an active accept call open as long as the transport is active
            await _connectionLock.WaitAsync(cancellationToken);

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
                    var connection = await TunnelConnectionContextHttp2.ConnectAsync(_httpMessageInvoker, uri, cancellationToken);

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
}
// public class TunnelConnectionListenerWebTransport: TunnelConnectionListenerProtocol { }
