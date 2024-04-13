using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Yarp.ReverseProxy.Tunnel;
internal class TunnelHandler
{
    internal static async Task<IResult> HandleHttp2Tunnel(HttpContext context)
    {
        // HTTP/2 duplex stream
        if (context.Request.Protocol != HttpProtocol.Http2)
        {
            return Results.BadRequest();
        }

        if (!(context.Request.RouteValues.TryGetValue("TunnelId", out var objTunnelId)
            && objTunnelId is string tunnelId))
        {
            tunnelId = string.Empty;
        }

        if (string.IsNullOrEmpty(tunnelId))
        {
            return Results.BadRequest();
        }
        
        var tunnelFactory = context.RequestServices.GetRequiredService<ForwarderTunnelClientFactory>();
        var lifetime = context.RequestServices.GetRequiredService<IHostApplicationLifetime>();

#warning host -> channel = tunnel || host or channel = tunnel

        var (requests, responses) = tunnelFactory.GetConnectionChannel(tunnelId);

        await requests.Reader.ReadAsync(context.RequestAborted);

        var stream = new DuplexHttpStream(context);

        using var reg = lifetime.ApplicationStopping.Register(() => stream.Abort());

        // Keep reusing this connection while, it's still open on the backend
        while (!context.RequestAborted.IsCancellationRequested)
        {
            // Make this connection available for requests
            await responses.Writer.WriteAsync(stream, context.RequestAborted);

            await stream.StreamCompleteTask;

            stream.Reset();
        }

        return Yarp.ReverseProxy.Tunnel.EmptyResult.Instance;
    }

#if false
    internal static async Task<IResult> HandleWebSocketTunnel(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            return Results.BadRequest();
        }

        if (!(context.Request.RouteValues.TryGetValue("TunnelId", out var objTunnelId)
            && objTunnelId is string tunnelId))
        {
            tunnelId = string.Empty;
        }

        var tunnelFactory = context.RequestServices.GetRequiredService<TunnelClientFactory>();
        var lifetime = context.RequestServices.GetRequiredService<IHostApplicationLifetime>();


        var (requests, responses) = tunnelFactory.GetConnectionChannel(tunnelId);

        await requests.Reader.ReadAsync(context.RequestAborted);

        var ws = await context.WebSockets.AcceptWebSocketAsync();

        var stream = new WebSocketStream(ws);

        // We should make this more graceful
        using var reg = lifetime.ApplicationStopping.Register(() => stream.Abort());

        // Keep reusing this connection while, it's still open on the backend
        while (ws.State == WebSocketState.Open)
        {
            // Make this connection available for requests
            await responses.Writer.WriteAsync(stream, context.RequestAborted);

            await stream.StreamCompleteTask;

            stream.Reset();
        }

        return Yarp.ReverseProxy.Tunnel.EmptyResult.Instance;
    }
#endif
}
