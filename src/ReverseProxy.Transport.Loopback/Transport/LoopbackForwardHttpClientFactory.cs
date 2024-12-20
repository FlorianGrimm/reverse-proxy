// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Transport;

internal sealed class LoopbackForwardHttpClientFactory
    : ILoopbackForwardHttpClientFactory
{
    private readonly TransportTunnelLoopbackOptions _options;
    private readonly ILogger<LoopbackForwardHttpClientFactory> _logger;
    //private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    //private ObjectPool<TunnelConnectionRequest> _poolTunnelConnectionRequest;

    public LoopbackForwardHttpClientFactory(
        IOptions<TransportTunnelLoopbackOptions> options,
        //TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<LoopbackForwardHttpClientFactory> logger
        )
    {
        _options = options.Value;
        _logger = logger;

        // _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        // _poolTunnelConnectionRequest = new DefaultObjectPool<TunnelConnectionRequest>(
        //     new TunnelConnectionRequest.TCRPooledObjectPolicy(logger));
    }

    public HttpMessageHandler CreateHttpMessageHandler()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            EnableMultipleHttp2Connections = true,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current),
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };

        //handler.ConnectCallback = async (connectionContext, cancellationToken) =>
        //{
        //    var socketPath = _options.SocketPath ?? throw new InvalidOperationException("SocketPath is empty");
        //    // Define the type of socket we want, i.e. a UDS stream-oriented socket
        //    var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);

        //    // Create a UDS endpoint using the socket path
        //    var endpoint = new UnixDomainSocketEndPoint(socketPath);

        //    // Connect to the server!
        //    await socket.ConnectAsync(endpoint, cancellationToken);

        //    // Wrap the socket in a NetworkStream and return it
        //    // Setting ownsSocket: true means the NetworkStream will 
        //    // close and dispose the Socket when the stream is disposed
        //    return new NetworkStream(socket, ownsSocket: true);
        //};
        return handler;
    }

    public HttpClient CreateHttpClient()
    {
        var result = new HttpClient(CreateHttpMessageHandler(), true);
        result.BaseAddress = new Uri("https://localhost:5101");
        return result;
    }
}
