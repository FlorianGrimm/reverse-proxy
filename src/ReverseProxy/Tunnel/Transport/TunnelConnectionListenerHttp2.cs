using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;

using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace Yarp.ReverseProxy.Tunnel.Transport;

internal class TunnelConnectionListenerHttp2 : TunnelConnectionListenerProtocol
{
    public TunnelConnectionListenerHttp2(
        UriTunnelTransportEndPoint uriTunnelTransportEndPoint,
        string tunnelId,
        TunnelBackendToFrontendState backendToFrontend,
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        TunnelBackendOptions options,
        ILogger<TunnelConnectionListenerHttp2> logger)
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
                Log.TunnelBackendToFrontendNotFound(_logger, tunnelId);

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
                    var connection = await ConnectAsync(invoker, uri, cancellationToken);

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

    protected override async Task<TrackLifetimeConnectionContext> ConnectAsync(HttpMessageInvoker invoker, Uri uri, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Version = new Version(2, 0)
        };
        var connection = new TunnelConnectionContextHttp2();
        request.Content = new HttpClientConnectionContextContent(connection);
        var response = await invoker.SendAsync(request, cancellationToken).ConfigureAwait(false);
        connection.HttpResponseMessage = response;
        var responseStream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        connection.Input = PipeReader.Create(responseStream);

        return new TrackLifetimeConnectionContext(connection);

    }

    protected override Uri GetRemoteUrl(TunnelBackendToFrontendState tunnel)
    {
        var url = tunnel.Url;
        var uri = new Uri(new Uri(url), $"/Tunnel/HTTP2/{tunnel.RemoteTunnelId}/{tunnel.RemoteHost}");
        return uri;
    }


    /*
    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _tunnelBackendToFrontendNotFound = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.TunnelBackendToFrontendNotFound,
            "TunnelBackendToFrontend '{tunnelId}' was not found.");

        public static void TunnelBackendToFrontendNotFound(ILogger logger, string tunnelId)
        {
            _tunnelBackendToFrontendNotFound(logger, tunnelId, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _tunnelConnectionListenerAdd = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.TunnelConnectionListenerAdd,
            "TunnelConnectionListener '{tunnelId}' as '{transport}' to '{url}' was added.");

        public static void TunnelConnectionListenerAdd(ILogger logger, string tunnelId, string transport, string url)
        {
            _tunnelConnectionListenerAdd(logger, tunnelId, transport, url, null);
        }
    }
    */
}
// public class TunnelConnectionListenerWebTransport: TunnelConnectionListenerProtocol { }
