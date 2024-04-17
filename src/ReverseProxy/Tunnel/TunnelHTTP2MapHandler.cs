using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal class TunnelHTTP2MapHandler : ITunnelHandler
{
    private readonly ProxyTunnelConfigManager _proxyTunnelConfigManager;
    private readonly TunnelFrontendToBackendState _tunnelFrontendToBackend;
    private readonly IForwarderHttpClientFactory _forwarderHttpClientFactory;

    private ImmutableDictionary<string, ActiveTunnelConnection> _connectionsById = ImmutableDictionary<string, ActiveTunnelConnection>.Empty;
    private ImmutableDictionary<string, ImmutableList<ActiveTunnelConnection>> _connectionsByHost = ImmutableDictionary<string, ImmutableList<ActiveTunnelConnection>>.Empty;

    public TunnelHTTP2MapHandler(
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        TunnelFrontendToBackendState tunnelFrontendToBackend,
        IForwarderHttpClientFactory forwarderHttpClientFactory)
    {
        _proxyTunnelConfigManager = proxyTunnelConfigManager;
        _tunnelFrontendToBackend = tunnelFrontendToBackend;
        _forwarderHttpClientFactory = forwarderHttpClientFactory;
    }

    public IEndpointConventionBuilder Map(IEndpointRouteBuilder endpoints)
    {
        var path = $"/Tunnel/HTTP2/{_tunnelFrontendToBackend.TunnelId}/{{Host}}";
        var builder = endpoints.MapPost(path, async (HttpContext context) => await HandleMapPost(context));
        // TODO: auth ?? builder.RequireAuthorization();
        return builder;
    }

    private async Task<IResult> HandleMapPost(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context, nameof(context));

        // HTTP/2 duplex stream
        if (context.Request.Protocol != HttpProtocol.Http2)
        {
            return Results.BadRequest();
        }

        // TODO: auth

        if (!context.Request.RouteValues.TryGetValue("Host", out var objHost)
            || objHost is not string host
            || string.IsNullOrWhiteSpace(host))
        {
            return Results.BadRequest();
        }

        var activeTunnel = RegisterTunnelConnection(context, host);
        try
        {
            var lifetime = context.RequestServices.GetRequiredService<IHostApplicationLifetime>();

            await activeTunnel.Requests.Reader.ReadAsync(context.RequestAborted);

            using var stream = new DuplexHttpStream(context);

            using var reg = lifetime.ApplicationStopping.Register(() => stream.Abort());

            // Keep reusing this connection while, it's still open on the backend
            while (!context.RequestAborted.IsCancellationRequested)
            {
                // Make this connection available for requests
                await activeTunnel.Responses.Writer.WriteAsync(stream, context.RequestAborted);

                await stream.StreamCompleteTask;

                stream.Reset();
            }

            return Yarp.ReverseProxy.Tunnel.EmptyResult.Instance;
        }
        finally
        {
            UnregisterConnection(activeTunnel);
        }
    }

    private ActiveTunnelConnection RegisterTunnelConnection(HttpContext context, string host)
    {
        var id = context.Connection.Id;
        var activeTunnel = new ActiveTunnelConnection(id, host, Channel.CreateUnbounded<int>(), Channel.CreateUnbounded<Stream>());
        while (true)
        {
            var old = _connectionsById;
            var next = old.Add(id, activeTunnel);
            if (ReferenceEquals(
                System.Threading.Interlocked.CompareExchange(ref _connectionsById, next, old),
                old))
            {
                break;
            }
        }
        while (true)
        {
            var old = _connectionsByHost;
            ImmutableDictionary<string, ImmutableList<ActiveTunnelConnection>> next;
            if (old.TryGetValue(host, out var oldList))
            {
                next = old.SetItem(host, oldList.Add(activeTunnel));
            }
            else
            {
                next = old.Add(host, ImmutableList.Create(activeTunnel));
            }
            if (ReferenceEquals(
                System.Threading.Interlocked.CompareExchange(ref _connectionsByHost, next, old),
                old))
            {
                break;
            }
        }

        _proxyTunnelConfigManager.UpdateMemoryConfigProvider(null);

        return activeTunnel;

    }

    private void UnregisterConnection(ActiveTunnelConnection activeTunnel)
    {
        var id = activeTunnel.Id;
        while (true)
        {
            var old = _connectionsById;
            var next = old.Remove(id);
            if (ReferenceEquals(
                System.Threading.Interlocked.CompareExchange(ref _connectionsById, next, old),
                old))
            {
                break;
            }
        }

        var host = activeTunnel.Address;
        while (true)
        {
            var old = _connectionsByHost;
            ImmutableDictionary<string, ImmutableList<ActiveTunnelConnection>> next;
            if (old.TryGetValue(host, out var oldList))
            {
                var nextList = oldList.Remove(activeTunnel);
                next = old.SetItem(host, nextList);
            }
            else
            {
                break;
            }

            if (ReferenceEquals(
                System.Threading.Interlocked.CompareExchange(ref _connectionsByHost, next, old),
                old))
            {
                break;
            }
        }

        _proxyTunnelConfigManager.UpdateMemoryConfigProvider(null);
    }


    private int _indexGetConnectionChannel = 0;
    public bool TryGetConnectionChannel(
        string host,
        [MaybeNullWhen(false)] out ActiveTunnelConnection activeTunnel)
    {
        // TODO: ILoadBalancingPolicy would be nicer...
        if (_connectionsByHost.TryGetValue(host, out var activeTunnels))
        {
            for (var iWatchDog = activeTunnels.Count; 0 < iWatchDog && 0 < activeTunnels.Count; iWatchDog--)
            {
                var index = (_indexGetConnectionChannel + 1) % activeTunnels.Count;
                _indexGetConnectionChannel = index;

                activeTunnel = activeTunnels[index];
                if (!activeTunnel.IsClosed)
                {
                    return true;
                }
            }
        }

        {
            activeTunnel = default;
            return false;
        }
    }

    public bool TryGetTunnelConnectionChannel(
        SocketsHttpConnectionContext socketsContext,
        [MaybeNullWhen(false)] out ActiveTunnelConnection activeTunnel)
    {
        var host = socketsContext.DnsEndPoint.Host;
        return TryGetConnectionChannel(host, out activeTunnel);
    }

    public Dictionary<string, DestinationConfig> GetDestinations()
    {
        var result = new Dictionary<string, DestinationConfig>(StringComparer.OrdinalIgnoreCase);
        foreach (var activeTunnels in _connectionsByHost.Values)
        {
            foreach (var activeTunnel in activeTunnels)
            {
                var destination = new DestinationConfig
                {
                    Address = activeTunnel.Address,
                    Health = nameof(DestinationHealth.Healthy),
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        { "TunnelId", _tunnelFrontendToBackend.TunnelId }
                    }
                };
                result.Add($"{activeTunnel.Address}-{activeTunnel.Id}", destination);
            }
        }
        return result;
    }

    public string GetTransport()
    {
        return "TunnelHTTP2";
    }
}

public record class ActiveTunnelConnection(
    string Id,
    string Address,
    Channel<int> Requests,
    Channel<Stream> Responses
    )
{
    public bool IsClosed { get; set; }
}
