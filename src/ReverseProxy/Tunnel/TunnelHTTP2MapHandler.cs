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
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

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
    private readonly ILogger<TunnelHTTP2MapHandler> _logger;
    private readonly ConcurrentDictionary<string, ActiveTunnelConnection> _connectionsByHost = new(StringComparer.OrdinalIgnoreCase);

    public TunnelHTTP2MapHandler(
        ProxyTunnelConfigManager proxyTunnelConfigManager,
        TunnelFrontendToBackendState tunnelFrontendToBackend,
        IForwarderHttpClientFactory forwarderHttpClientFactory,
        ILogger<TunnelHTTP2MapHandler> logger)
    {
        _proxyTunnelConfigManager = proxyTunnelConfigManager;
        _tunnelFrontendToBackend = tunnelFrontendToBackend;
        _forwarderHttpClientFactory = forwarderHttpClientFactory;
        _logger = logger;
    }

    public IEndpointConventionBuilder Map(IEndpointRouteBuilder endpoints)
    {
        var path = $"/Tunnel/HTTP2/{_tunnelFrontendToBackend.TunnelId}/{{Host}}";
        var builder = endpoints.MapPost(path, async (HttpContext context) => await HandleMapPost(context));
        Log.TunnelMapAdded(_logger, path);
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

        var activeTunnel = RegisterTunnelConnection(host);
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

    private ActiveTunnelConnection RegisterTunnelConnection(string host)
    {
        int count;
        if (_connectionsByHost.TryGetValue(host, out var result))
        {
            count = System.Threading.Interlocked.Increment(ref result.Count);
        }
        else
        {
            result = _connectionsByHost.GetOrAdd(host, _ => new ActiveTunnelConnection(host, Channel.CreateUnbounded<int>(), Channel.CreateUnbounded<Stream>()));
            count = System.Threading.Interlocked.Increment(ref result.Count);
        }
        if (count == 1)
        {
            _proxyTunnelConfigManager.UpdateMemoryConfigProvider(null);
        }
        Log.TunnelConnectionAdded(_logger, _tunnelFrontendToBackend.Transport, _tunnelFrontendToBackend.TunnelId, host);

        return result;
    }

    private void UnregisterConnection(ActiveTunnelConnection activeTunnel)
    {
        var count = System.Threading.Interlocked.Decrement(ref activeTunnel.Count);
        if (count == 0)
        {
            _proxyTunnelConfigManager.UpdateMemoryConfigProvider(null);
        }
    }

    
    public bool TryGetConnectionChannel(
        string host,
        [MaybeNullWhen(false)] out ActiveTunnelConnection activeTunnel)
    {
        // TODO: ILoadBalancingPolicy would be nicer...
        if (_connectionsByHost.TryGetValue(host, out activeTunnel))
        {
            return true;
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
        foreach (var activeTunnel in _connectionsByHost.Values)
        {
            var address = activeTunnel.Address;
            if (address.StartsWith("https://") || address.StartsWith("http://") || address.Contains("://"))
            {
            }
            else
            {
                address = "http://" + address;
            }

            var destination = new DestinationConfig
            {
                Address = address,
                Health = nameof(DestinationHealth.Healthy),
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        { "TunnelId", _tunnelFrontendToBackend.TunnelId }
                    }
            };
            result.Add($"{activeTunnel.Address}-{activeTunnel.Id}", destination);
        }
        return result;
    }

    public string GetTransport()
    {
        return "TunnelHTTP2";
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _tunnelMapAdded = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.TunnelMapAdded,
            "TunnelMap '{path}' has been added.");

        public static void TunnelMapAdded(ILogger logger, string path)
        {
            _tunnelMapAdded(logger, path, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _tunnelConnectionAdded = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.TunnelMapAdded,
            "TunnelConnection '{transport}' '{tunnelId}' '{host}' has been added.");

        public static void TunnelConnectionAdded(ILogger logger, string transport, string tunnelId, string host)
        {
            _tunnelConnectionAdded(logger, transport, tunnelId, host, null);
        }
    }
}

public record class ActiveTunnelConnection(
    string Address,
    Channel<int> Requests,
    Channel<Stream> Responses
    )
{
    private string? _Id;

    public string Id => _Id ??= Guid.NewGuid().ToString();

    public int Count = 0;

    public bool IsClosed => Count == 0;
}
