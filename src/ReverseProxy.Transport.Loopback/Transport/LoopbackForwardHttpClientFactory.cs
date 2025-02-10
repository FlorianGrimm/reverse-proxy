// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CA1513 // ObjectDisposedException.ThrowIf does not exist in dotnet 6.0

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
    private bool _isDisposed;
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
