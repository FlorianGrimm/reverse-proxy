// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using static Yarp.ReverseProxy.Tunnel.TunnelConnectionRequest;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelWebSocketHttpClientFactoryForCluster
    : IForwarderHttpClientFactory
    , IDisposable
{
    private ObjectPool<TunnelConnectionRequest> _poolTunnelConnectionRequest;
    private readonly ProxyConfigManager _proxyConfigManager;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly string _clusterId;
    private readonly ILogger _logger;
    private bool _isDisposed;

    public TunnelWebSocketHttpClientFactoryForCluster(
        ProxyConfigManager proxyConfigManager,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        string clusterId,
        ILogger logger)
    {
        _proxyConfigManager = proxyConfigManager;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _clusterId = clusterId;
        _logger = logger;
        _poolTunnelConnectionRequest = new DefaultObjectPool<TunnelConnectionRequest>(
                new TunnelConnectionRequest.TCRPooledObjectPolicy(logger));
    }

    public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        var clusterId = context.ClusterId;

        if (!string.Equals(clusterId, _clusterId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Unexpected clusterid");
        }

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

            handler.ConnectCallback = async (context, cancellationToken) =>
            {
                if (_isDisposed)
                {
                    throw new ObjectDisposedException(nameof(TunnelHTTP2HttpClientFactoryForCluster));
                }
                if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(clusterId, out var tunnelConnectionChannels))
                {
                    throw new InvalidOperationException("tunnelConnectionChannels not found");
                }
                var channelTCRWriter = tunnelConnectionChannels.Writer;

                System.Threading.Interlocked.Increment(ref tunnelConnectionChannels.CountSink);

                var tunnelConnectionRequest = _poolTunnelConnectionRequest.Get();
                try
                {
                    while (true)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        // Ask for a/another connection
                        await channelTCRWriter.WriteAsync(tunnelConnectionRequest, cancellationToken);
                        var stream = await tunnelConnectionRequest.GetStreamAsync(cancellationToken);
                        if ((stream is null)
                            || (stream is IStreamCloseable c && c.IsClosed))
                        {
                            if (_isDisposed)
                            {
                                throw new ObjectDisposedException(nameof(TunnelHTTP2HttpClientFactoryForCluster));
                            }
                            tunnelConnectionRequest = tunnelConnectionRequest.GetReseted() ?? _poolTunnelConnectionRequest.Get();
                            continue;
                        }

                        return stream;
                    }
                }
                catch (OperationCanceledException error)
                {
                    tunnelConnectionRequest.Failed();
                    _logger.LogInformation(error, "ConnectCallback request canceled {clusterId}", _clusterId);
                    throw;
                }
                catch (Exception error)
                {
                    tunnelConnectionRequest.Failed();
                    _logger.LogError(error, "ConnectCallback error {clusterId}", _clusterId);
                    throw;
                }
                finally
                {
                    System.Threading.Interlocked.Decrement(ref tunnelConnectionChannels.CountSink);
                    var pool = tunnelConnectionRequest.GetReseted();
                    if (pool is not null)
                    {
                        _poolTunnelConnectionRequest.Return(pool);
                    }
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

    private void Dispose(bool disposing)
    {
        _isDisposed = true;
        using (var poolTunnelConnectionRequest = _poolTunnelConnectionRequest as IDisposable)
        {
            if (disposing)
            {
                _poolTunnelConnectionRequest = null!;
            }
        }
    }

    ~TunnelWebSocketHttpClientFactoryForCluster()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
