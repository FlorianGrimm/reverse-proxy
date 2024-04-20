using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Tunnel;


namespace Yarp.ReverseProxy.Forwarder;

/// <summary>
/// Base class for forwarder factories that use a tunnel to connect to the backend.
/// </summary>
public abstract class ForwarderTunnelHttpClientFactory
    : ForwarderBaseClientFactory
    , IForwarderHttpClientFactorySelectiv
{
    protected readonly IProxyTunnelConfigManager _proxyTunnelConfigManager;

    protected ForwarderTunnelHttpClientFactory(
        IProxyTunnelConfigManager proxyTunnelConfigManager,
        ILogger logger)
        : base(logger)
    {
        _proxyTunnelConfigManager = proxyTunnelConfigManager;
    }


    protected override SocketsHttpHandler CreateSocketsHttpHandler(ForwarderHttpClientContext context)
    {
        var handler = base.CreateSocketsHttpHandler(context);

        if (!_proxyTunnelConfigManager.TryGetTunnelFrontendToBackend(context.ClusterId, out var tunnelFrontendToBackendState))
        {
            // TODO: return 503 Service Unavailable? log?
            throw new NotSupportedException("TunnelFrontendToBackend not found");
        }

        handler.ConnectCallback = (SocketsHttpConnectionContext socketsContext, CancellationToken cancellationToken) =>
        {
            return ConnectSocketsHttpHandler(context, socketsContext, cancellationToken);
        };

        return handler;
    }


    protected virtual async ValueTask<Stream> ConnectSocketsHttpHandler(
        ForwarderHttpClientContext context,
        SocketsHttpConnectionContext socketsContext,
        CancellationToken cancellationToken)
    {

        if (!_proxyTunnelConfigManager.TryGetTunnelFrontendToBackend(context.ClusterId, out var tunnelFrontendToBackendState))
        {
            // TODO: return 503 Service Unavailable? log?
            throw new NotSupportedException();
        }
        if (!_proxyTunnelConfigManager.TryGetTunnelHandler(context.ClusterId, out var tunnelHandler))
        {
            // TODO: return 503 Service Unavailable? log?
            throw new NotSupportedException();
        }
        if (!tunnelHandler.TryGetTunnelConnectionChannel(socketsContext, out var activeTunnel))
        {
            // TODO: return 503 Service Unavailable
            // TODO: Help I have no idea how to do this properly
            throw new NotSupportedException("503");
        }

        var requests = activeTunnel.Requests;
        var responses = activeTunnel.Responses;

        // Ask for a connection
        var idxConnection = 1;
        await requests.Writer.WriteAsync(idxConnection++, cancellationToken);

        while (true)
        {
            var stream = await responses.Reader.ReadAsync(cancellationToken);
            // TODO: log telemetry ???

            if (stream is ICloseable c && c.IsClosed && !activeTunnel.IsClosed)
            {
                // Ask for another connection
                await requests.Writer.WriteAsync(idxConnection++, cancellationToken);

                continue;
            }

            return stream;
        }
    }
}

