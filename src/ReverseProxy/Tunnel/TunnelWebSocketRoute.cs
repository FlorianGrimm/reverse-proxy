using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

using Microsoft.Extensions.Hosting;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelWebSocketRoute
{
    private readonly UnShortCitcuitOnceProxyConfigManager _unShortCitcuitOnceProxyConfigManager;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    public TunnelWebSocketRoute(
        UnShortCitcuitOnceProxyConfigManager unShortCitcuitOnceProxyConfigManager,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        IHostApplicationLifetime lifetime,
        ILogger<TunnelWebSocketRoute> logger)
    {
        _unShortCitcuitOnceProxyConfigManager = unShortCitcuitOnceProxyConfigManager;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _lifetime = lifetime;
        _logger = logger;

        _lifetime.ApplicationStopping.Register(() => _cancellationTokenSource.Cancel());
    }

    
    internal IEndpointConventionBuilder Map(
        IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configure)
    {
        // TODO: EnableRequestDelegateGenerator does not work
#pragma warning disable IL2026
        var conventionBuilder = endpoints.MapGet("_Tunnel/{clusterId}", TunnelWebSocketRouteGet);
#pragma warning restore IL2026

        // Make this endpoint do websockets automagically as middleware for this specific route
        conventionBuilder.Add(e =>
        {
            var sub = endpoints.CreateApplicationBuilder();
            sub.UseWebSockets().Run(e.RequestDelegate!);
            e.RequestDelegate = sub.Build();
        });

        if (configure is not null)
        {
            configure(conventionBuilder);
        }

        return conventionBuilder;
    }

    private async Task<IResult> TunnelWebSocketRouteGet(HttpContext context, string clusterId)
    {
        //if (context.GetRouteValue("clusterId") is not string clusterId)
        //{
        //    // TODO: log
        //    return Results.BadRequest();
        //}

        if (!context.WebSockets.IsWebSocketRequest)
        {
            return Results.BadRequest();
        }

        var proxyConfigManager = _unShortCitcuitOnceProxyConfigManager.GetService();
        if (!proxyConfigManager.TryGetCluster(clusterId, out var cluster))
        {
            // TODO: log
#warning TODO
            return Results.BadRequest();
        }

        if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(clusterId, out var tunnelConnectionChannels))
        {
            // TODO: log
#warning TODO
            return Results.BadRequest();
        }


        var (requests, responses) = tunnelConnectionChannels;
        using (var ctsRequestAborted = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, _cancellationTokenSource.Token))
        {
            var responsesWriter = responses.Writer;
            await requests.Reader.ReadAsync(ctsRequestAborted.Token);

            using (var ws = await context.WebSockets.AcceptWebSocketAsync())
            {
                using (var stream = new TunnelWebSocketStream(ws))
                {
                    // We should make this more graceful
                    using (var reg = _lifetime.ApplicationStopping.Register(() => stream.Abort()))
                    {
                        // Keep reusing this connection while, it's still open on the backend
                        while (ws.State == WebSocketState.Open)
                        {
                            // Make this connection available for requests
                            await responsesWriter.WriteAsync(stream, ctsRequestAborted.Token);
                            await stream.StreamCompleteTask;
                            stream.Reset();
                        }
                    }
                }
            }
        }

        return EmptyResult.Instance;
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _parameterNotValid = LoggerMessage.Define<string>(
            LogLevel.Warning,
            EventIds.ParameterNotValid,
            "Requiered Parameter {name} - value is not valid.");

        public static void ParameterNotValid(ILogger logger, string parameterName)
        {
            _parameterNotValid(logger, parameterName, null);
        }

        private static readonly Action<ILogger, string, Exception?> _clusterNotFound = LoggerMessage.Define<string>(
            LogLevel.Warning,
            EventIds.ClusterNotFound,
            "Cluster {name} not found.");

        public static void ClusterNotFound(ILogger logger, string parameterName)
        {
            _clusterNotFound(logger, parameterName, null);
        }

        private static readonly Action<ILogger, string, Exception?> _tunnelConnectionChannelNotFound = LoggerMessage.Define<string>(
            LogLevel.Warning,
            EventIds.TunnelConnectionChannelNotFound,
            "TunnelConnectionChannel {name} not found.");

        public static void TunnelConnectionChannelNotFound(ILogger logger, string parameterName)
        {
            _tunnelConnectionChannelNotFound(logger, parameterName, null);
        }

        /*
        private static readonly Action<ILogger, string, Exception?> _hugo = LoggerMessage.Define<string>(
            LogLevel.Warning,
            EventIds.ParameterNotValid,
            " {name} is not valid.");

        public static void Hugo(ILogger logger, string parameterName) {
            _hugo(logger, parameterName, null);
        }
        */
    }
}
