using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelHTTP2HttpClientFactory
    : ITransportHttpClientFactorySelector
{
    private readonly ConcurrentDictionary<string, TunnelHTTP2HttpClientFactoryBound> _tunnelHTTP2HttpClientFactoryBoundByClusterId = new();
    private readonly UnShortCitcuitOnceProxyConfigManager _unShortCitcuitOnceProxyConfigManager;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger _logger;

    public TunnelHTTP2HttpClientFactory(
        UnShortCitcuitOnceProxyConfigManager unShortCitcuitOnceProxyConfigManager,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<TunnelHTTP2HttpClientFactory> logger)
    {
        _unShortCitcuitOnceProxyConfigManager = unShortCitcuitOnceProxyConfigManager;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
    }

    public TransportMode GetTransportMode() => TransportMode.TunnelHTTP2;

    public int GetOrder() => 0;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(
        TransportMode transportMode,
        ForwarderHttpClientContext context)
    {
        while (true)
        {
            if (!_tunnelHTTP2HttpClientFactoryBoundByClusterId.TryGetValue(context.ClusterId, out var result))
            {
                result = new TunnelHTTP2HttpClientFactoryBound(
                    _unShortCitcuitOnceProxyConfigManager.GetService(),
                    _tunnelConnectionChannelManager,
                    _logger);
                if (_tunnelHTTP2HttpClientFactoryBoundByClusterId.TryAdd(context.ClusterId, result))
                {
                    return result;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                return result;
            }
        }
    }
}

internal sealed class TunnelHTTP2HttpClientFactoryBound : IForwarderHttpClientFactory
{
    private readonly ProxyConfigManager _proxyConfigManager;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger _logger;

    public TunnelHTTP2HttpClientFactoryBound(
        ProxyConfigManager proxyConfigManager,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger logger)
    {
        _proxyConfigManager = proxyConfigManager;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
    }

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        var clusterId = context.ClusterId;

        if (CanReuseOldClient(context))
        {
            Log.ClientReused(_logger, context.ClusterId);
            return context.OldClient!;
        }

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

                // NOTE: MaxResponseHeadersLength = 64, which means up to 64 KB of headers are allowed by default as of .NET Core 3.1.
            };

            ConfigureHandler(context, handler);

            handler.ConnectCallback = async (context, cancellationToken) => {
                //var channelId = context.DnsEndPoint.Host;
                if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(clusterId, out var tunnelConnectionChannels))
                {
                    throw new InvalidOperationException("tunnelConnectionChannels not found");
                }
                var (requests, responses) = tunnelConnectionChannels;

                System.Threading.Interlocked.Increment(ref tunnelConnectionChannels.CountSink);
                var requestsWriter = requests.Writer;
                var responsesReader = responses.Reader;
                try
                {

                    // Ask for a connection
                    var retry = 0;
                    await requestsWriter.WriteAsync(retry++, cancellationToken);

                    while (true)
                    {
                        var stream = await responsesReader.ReadAsync(cancellationToken);

                        if (stream is IStreamCloseable c && c.IsClosed)
                        {
                            // Ask for another connection
                            await requestsWriter.WriteAsync(retry++, cancellationToken);
                            continue;
                        }

                        return stream;
                    }
                }
                finally
                {
                    System.Threading.Interlocked.Decrement(ref tunnelConnectionChannels.CountSink);
                }
            };

            Log.ClientCreated(_logger, context.ClusterId);

            return new HttpMessageInvoker(handler, disposeHandler: true);
        }
    }

    /// <summary>
    /// Checks if the options have changed since the old client was created. If not then the
    /// old client will be re-used. Re-use can avoid the latency of creating new connections.
    /// </summary>
    private bool CanReuseOldClient(ForwarderHttpClientContext context)
    {
        return context.OldClient is not null && context.NewConfig == context.OldConfig;
    }

    /// <summary>
    /// Allows configuring the <see cref="SocketsHttpHandler"/> instance. The base implementation
    /// applies settings from <see cref="ForwarderHttpClientContext.NewConfig"/>.
    /// <see cref="SocketsHttpHandler.UseProxy"/>, <see cref="SocketsHttpHandler.AllowAutoRedirect"/>,
    /// <see cref="SocketsHttpHandler.AutomaticDecompression"/>, and <see cref="SocketsHttpHandler.UseCookies"/>
    /// are disabled prior to this call.
    /// </summary>
    private void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        var newConfig = context.NewConfig;
        // TODO: the inner connection is always http no s
#if WEICHEI
        if (newConfig.SslProtocols.HasValue) {
            handler.SslOptions.EnabledSslProtocols = newConfig.SslProtocols.Value;
        }
        if (newConfig.MaxConnectionsPerServer is not null) {
            handler.MaxConnectionsPerServer = newConfig.MaxConnectionsPerServer.Value;
        }
        if (newConfig.DangerousAcceptAnyServerCertificate ?? false) {
            handler.SslOptions.RemoteCertificateValidationCallback = delegate { return true; };
        }
#endif
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
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _clientCreated = LoggerMessage.Define<string>(
              LogLevel.Debug,
              EventIds.ClientCreated,
              "New client created for cluster '{clusterId}'.");

        private static readonly Action<ILogger, string, Exception?> _clientReused = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.ClientReused,
            "Existing client reused for cluster '{clusterId}'.");

        public static void ClientCreated(ILogger logger, string clusterId)
        {
            _clientCreated(logger, clusterId, null);
        }

        public static void ClientReused(ILogger logger, string clusterId)
        {
            _clientReused(logger, clusterId, null);
        }
    }
}
