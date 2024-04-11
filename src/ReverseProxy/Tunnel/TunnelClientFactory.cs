// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;


namespace Yarp.ReverseProxy.Tunnel
{
    /// <summary>
    /// The factory that YARP will use the create outbound connections by host name.
    /// </summary>
    internal class TunnelClientFactory : ForwarderHttpClientFactory, IForwarderTransportClientFactory
    {
        //private readonly IProxyConfigProvider _proxyConfigProvider;

        public TunnelClientFactory(
            //IProxyConfigProvider proxyConfigProvider,
            ILogger<TunnelClientFactory> logger
            ) : base(logger)
        {
            //_proxyConfigProvider = proxyConfigProvider;

            /*
            var proxyConfig = proxyConfigProvider.GetConfig();
            foreach (var cluster in proxyConfig.Clusters) {
                if (cluster.Metadata is not null
                    && cluster.Metadata.TryGetValue("Transport", out var transport)
                    && string.Equals(transport, "Tunnel", StringComparison.Ordinal)
                    ) {
                    if (cluster.Destinations is not null) {
                        foreach (var destination in cluster.Destinations.Values) {
#warning                    destination.Address
                        }
                    }
                }
            }
            */
        }

        public override string? GetTransport() => "Tunnel";

#warning How do i get the channel / tunnel?

        // TODO: These values should be populated by configuration so there's no need to remove
        // channels.
        private readonly ConcurrentDictionary<string, (Channel<int>, Channel<Stream>)> _clusterConnections = new();

        public (Channel<int>, Channel<Stream>) GetConnectionChannel(string host)
        {
            return _clusterConnections.GetOrAdd(host, _ => (Channel.CreateUnbounded<int>(), Channel.CreateUnbounded<Stream>()));
        }


        protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
        {
            base.ConfigureHandler(context, handler);

            var previous = handler.ConnectCallback ?? DefaultConnectCallback;

            //v context.ClusterId

            static async ValueTask<Stream> DefaultConnectCallback(SocketsHttpConnectionContext socketsContext, CancellationToken cancellationToken)
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(socketsContext.DnsEndPoint, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }


            handler.ConnectCallback = async (socketsContext, cancellationToken) =>
            {
                if (_clusterConnections.TryGetValue(socketsContext.DnsEndPoint.Host, out var pair))
                {
                    var (requests, responses) = pair;

                    // Ask for a connection
                    await requests.Writer.WriteAsync(0, cancellationToken);

                    while (true)
                    {
                        var stream = await responses.Reader.ReadAsync(cancellationToken);

                        if (stream is ICloseable c && c.IsClosed)
                        {
                            // Ask for another connection
                            await requests.Writer.WriteAsync(0, cancellationToken);

                            continue;
                        }

                        return stream;
                    }
                }
                return await previous(socketsContext, cancellationToken);
            };
        }
    }
}
