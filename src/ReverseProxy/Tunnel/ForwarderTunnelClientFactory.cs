// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.SessionAffinity;


namespace Yarp.ReverseProxy.Tunnel
{
    /// <summary>
    /// The factory that YARP will use the create outbound connections by host name.
    /// </summary>
    internal class ForwarderTunnelClientFactory : ForwarderTransportClientFactory, IForwarderTransportClientFactory
    {
        //private readonly ProxyConfigManager _proxyConfigManager;
        //private IChangeToken _proxyConfigManagerChangeToken;

        public ForwarderTunnelClientFactory(
            //ProxyConfigManager proxyConfigManager,
            IServiceProvider serviceProvider,
            ILogger<ForwarderTunnelClientFactory> logger
            ) : base(logger)
        {
            _serviceProvider = serviceProvider;
            //_proxyConfigManager = proxyConfigManager;
            // _proxyConfigManagerChangeToken = _proxyConfigManager.GetChangeToken();
            //foreach (var tunnelFrontendToBackend in _proxyConfigManager.GetTunnelFrontendToBackends()) {
            //    var tunnelId = tunnelFrontendToBackend.Config.TunnelId;
            //    // TODO: add tunnel - host
            //}


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

        /// <inheritdoc/>
        public override HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
        {

            if (CanReuseOldClient(context))
            {
                Log.ClientReused(_logger, context.ClusterId);
                return context.OldClient!;
            }

            var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false,
                ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current),
                ConnectTimeout = TimeSpan.FromSeconds(15),

                // NOTE: MaxResponseHeadersLength = 64, which means up to 64 KB of headers are allowed by default as of .NET Core 3.1.
            };

            ConfigureHandler(context, handler);

            var middleware = WrapHandler(context, handler);

            Log.ClientCreated(_logger, context.ClusterId);

            return new HttpMessageInvoker(middleware, disposeHandler: true);
        }

        /// <summary>
        /// Checks if the options have changed since the old client was created. If not then the
        /// old client will be re-used. Re-use can avoid the latency of creating new connections.
        /// </summary>
        protected override bool CanReuseOldClient(ForwarderHttpClientContext context)
        {
            return context.OldClient is not null && context.NewConfig == context.OldConfig;
        }

        public override string? GetTransport() => "Tunnel";

#warning How do i get the channel / tunnel?

        // TODO: These values should be populated by configuration so there's no need to remove
        // channels.
        private readonly ConcurrentDictionary<string, (Channel<int>, Channel<Stream>)> _clusterConnections = new();
        private readonly IServiceProvider _serviceProvider;

        public (Channel<int>, Channel<Stream>) GetConnectionChannel(string host)
        {
            return _clusterConnections.GetOrAdd(host, _ => (Channel.CreateUnbounded<int>(), Channel.CreateUnbounded<Stream>()));
        }


        protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
        {
            var newConfig = context.NewConfig;
            if (newConfig.SslProtocols.HasValue)
            {
                handler.SslOptions.EnabledSslProtocols = newConfig.SslProtocols.Value;
            }
            if (newConfig.MaxConnectionsPerServer is not null)
            {
                handler.MaxConnectionsPerServer = newConfig.MaxConnectionsPerServer.Value;
            }
            if (newConfig.DangerousAcceptAnyServerCertificate ?? false)
            {
                handler.SslOptions.RemoteCertificateValidationCallback = delegate { return true; };
            }

            handler.EnableMultipleHttp2Connections = newConfig.EnableMultipleHttp2Connections.GetValueOrDefault(true);

            if (newConfig.RequestHeaderEncoding is not null)
            {
                var encoding = Encoding.GetEncoding(newConfig.RequestHeaderEncoding);
                handler.RequestHeaderEncodingSelector = (_, _) => encoding;
            }

            if (newConfig.ResponseHeaderEncoding is not null)
            {
                var encoding = Encoding.GetEncoding(newConfig.ResponseHeaderEncoding);
                handler.ResponseHeaderEncodingSelector = (_, _) => encoding;
            }

            var webProxy = TryCreateWebProxy(newConfig.WebProxy);
            if (webProxy is not null)
            {
                handler.Proxy = webProxy;
                handler.UseProxy = true;
            }

            var previous = handler.ConnectCallback ?? DefaultConnectCallback;

            //v context.ClusterId

            static async ValueTask<Stream> DefaultConnectCallback(SocketsHttpConnectionContext socketsContext, CancellationToken cancellationToken)
            {
                var host = socketsContext.DnsEndPoint.Host;
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
                var host = socketsContext.DnsEndPoint.Host;
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
