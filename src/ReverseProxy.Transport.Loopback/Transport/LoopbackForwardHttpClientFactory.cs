// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Transport;

internal sealed class LoopbackForwardHttpClientFactory
    : ILoopbackForwardHttpClientFactory
    , System.IDisposable
{
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly ILogger<LoopbackForwardHttpClientFactory> _logger;
    private bool _isDisposed = false;
    private ObjectPool<TunnelConnectionRequest> _poolTunnelConnectionRequest;

    public LoopbackForwardHttpClientFactory(
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        ILogger<LoopbackForwardHttpClientFactory> logger
        )
    {
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _logger = logger;
        _poolTunnelConnectionRequest = new DefaultObjectPool<TunnelConnectionRequest>(
            new TunnelConnectionRequest.TCRPooledObjectPolicy(logger));

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
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
            }
        };

        handler.ConnectCallback = async (connectionContext, cancellationToken) =>
        {
            var result = await OnConnectCallback(connectionContext, cancellationToken);
            return result ?? Stream.Null;
        };
        return handler;
    }

    private async ValueTask<Stream?> OnConnectCallback(
          SocketsHttpConnectionContext connectionContext,
          CancellationToken cancellationToken)
    {
        if (_isDisposed)
        {
            throw new ObjectDisposedException(nameof(LoopbackForwardHttpClientFactory));
        }

        var host = connectionContext.DnsEndPoint.Host;
        // TODO: check host
        _logger.LogInformation("host:{host}", host);
        var clusterId = host; //TransportTunnelLoopbackConstants.LoopbackClusterId;
        if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(
            clusterId,
            out var tunnelConnectionChannels))
        {
            clusterId = TransportTunnelLoopbackConstants.LoopbackClusterId;
            if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(
                TransportTunnelLoopbackConstants.LoopbackClusterId
                , out tunnelConnectionChannels))
            {
                throw new InvalidOperationException($"tunnelConnectionChannels {clusterId} not found");
            }
        }
        var channelTCRWriter = tunnelConnectionChannels.Writer;

        // TODO: replace with proper monitoring??
        System.Threading.Interlocked.Increment(ref tunnelConnectionChannels.CountSink);

        var _clusterId = "TODO";

        var tunnelConnectionRequest = _poolTunnelConnectionRequest.Get();
        try
        {
            while (true)
            {
                if (_isDisposed || cancellationToken.IsCancellationRequested)
                {
                    tunnelConnectionRequest.Failed();
                    return null;
                }

                // Ask for a/another connection
                Stream? stream;
                try
                {
                    await channelTCRWriter.WriteAsync(tunnelConnectionRequest, cancellationToken);
                    _logger.LogDebug("ConnectCallback waiting for stream {clusterId}", _clusterId);
                    stream = await tunnelConnectionRequest.GetStreamAsync(cancellationToken);
                    _logger.LogDebug("ConnectCallback got stream {clusterId}", _clusterId);
                }
                catch (TaskCanceledException)
                {
                    return null;
                }
                if ((stream is null)
                    || (stream is IStreamCloseable c && c.IsClosed))
                {
                    if (_isDisposed) { return null; }

                    tunnelConnectionRequest = tunnelConnectionRequest.GetIfReusable() ?? _poolTunnelConnectionRequest.Get();
                    continue;
                }

                return stream;
            }
        }
        catch (OperationCanceledException error)
        {
            tunnelConnectionRequest.Failed();
            _logger.LogDebug(error, "ConnectCallback request canceled {clusterId}", _clusterId);
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
            // TODO: replace with proper monitoring??
            System.Threading.Interlocked.Decrement(ref tunnelConnectionChannels.CountSink);

            var backToPool = tunnelConnectionRequest.GetIfReusable();
            if (backToPool is not null)
            {
                _poolTunnelConnectionRequest.Return(backToPool);
            }
        }
    }


    public HttpClient CreateHttpClient()
    {
        var handler = CreateHttpMessageHandler();
        var result = new HttpClient(handler, true);
        result.BaseAddress = new Uri("http://loopback");
        return result;
    }

    public void Dispose()
    {
        _isDisposed = true;
        using (var poolTunnelConnectionRequest = _poolTunnelConnectionRequest as IDisposable)
        {
            _poolTunnelConnectionRequest = null!;
        }
    }
}

#if false
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
#endif
