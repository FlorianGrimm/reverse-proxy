using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Tunnel;
using Yarp.ReverseProxy.Management;
using System;
using Microsoft.AspNetCore.WebUtilities;
using Yarp.ReverseProxy.Model;
using System.Net;

namespace Yarp.ReverseProxy.Forwarder;

internal class ForwarderTunnelHTTP2ClientFactory
    : ForwarderTunnelHttpClientFactory
    , IForwarderHttpClientFactory
    , IForwarderHttpClientFactorySelectiv
{
    public const string Transport = "TunnelHTTP2";

    public ForwarderTunnelHTTP2ClientFactory(
        IProxyTunnelConfigManager proxyTunnelConfigManager,
        ILogger<ForwarderTunnelHTTP2ClientFactory> logger
        )
        : base(proxyTunnelConfigManager, logger) { }

    public override string GetTransport() => Transport;
}

#if false
internal class TunnelHttpMessageHandler : DelegatingHandler
{
    private readonly ForwarderHttpClientContext _context;
    private readonly ProxyTunnelConfigManager _proxyTunnelConfigManager;
    private readonly TunnelFrontendToBackendState _tunnelFrontendToBackendState;


    public TunnelHttpMessageHandler(
        ForwarderHttpClientContext context,
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        TunnelFrontendToBackendState tunnelFrontendToBackendState)
    {
        _context = context;
        _proxyTunnelConfigManager = proxyTunnelConfigManager;
        _tunnelFrontendToBackendState = tunnelFrontendToBackendState;
    }

    //protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    //{
    //    //var x = new SocketsHttpHandler();

    //    return base.Send(request, cancellationToken);
    //}

    //protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    //{
    //    return base.SendAsync(request, cancellationToken);
    //}

}
internal class TunnelHttpContent : HttpContent
{
    public TunnelHttpContent()
    {
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        throw new NotImplementedException();
    }

    protected override bool TryComputeLength(out long length)
    {
        throw new NotImplementedException();
    }
}
#endif

#if false


        if (!_proxyTunnelConfigManager.TryGetTunnelFrontendToBackend(context.ClusterId, out var tunnelFrontendToBackendState))
        {
            throw new NotSupportedException("TunnelFrontendToBackend not found");
        }
            
        handler.ConnectCallback = async (SocketsHttpConnectionContext socketsContext, CancellationToken cancellationToken) =>
        {
            if (!_proxyTunnelConfigManager.TryGetTunnelFrontendToBackend(context.ClusterId, out var tunnelFrontendToBackendState))
            {
                throw new NotSupportedException();
            }
            if (!_proxyTunnelConfigManager.TryGetTunnelHandler(context.ClusterId, out var tunnelHandler))
            {
                throw new NotSupportedException();
            }
            if (!tunnelHandler.TryGetTunnelConnectionChannel(socketsContext, out var activeTunnel))
            {
                // TODO: return 503 Service Unavailable
                var ms = new MemoryStream();
                var w = new HttpResponseStreamWriter(ms, System.Text.Encoding.UTF8);
                w.WriteLine("HTTP/1.1 503 Service Unavailable");
                w.Flush();
                w.Dispose();
                ms.Position = 0;
                return ms;
            }
            var requests = activeTunnel.Requests;
            var responses = activeTunnel.Responses;

            // Ask for a connection
            await requests.Writer.WriteAsync(0, cancellationToken);

            while (true)
            {
                var stream = await responses.Reader.ReadAsync(cancellationToken);

                if (stream is ICloseable c && c.IsClosed && !activeTunnel.IsClosed)
                {
                    // Ask for another connection
                    await requests.Writer.WriteAsync(0, cancellationToken);

                    continue;
                }

                return stream;
            }
        };

        return handler;
#endif
