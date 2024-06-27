// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.WebSockets;
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
    : IDisposable
{
    private readonly UnShortCitcuitProxyConfigManager _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly TunnelAuthenticationConfigService _tunnelAuthenticationConfigService;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger _logger;
    private CancellationTokenRegistration? _unRegister;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    public TunnelWebSocketRoute(
        UnShortCitcuitProxyConfigManager proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        TunnelAuthenticationConfigService tunnelAuthenticationConfigService,
        IHostApplicationLifetime lifetime,
        ILogger<TunnelWebSocketRoute> logger)
    {
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _tunnelConnectionChannelManager = tunnelConnectionChannelManager;
        _tunnelAuthenticationConfigService = tunnelAuthenticationConfigService;
        _lifetime = lifetime;
        _logger = logger;

        _unRegister = _lifetime.ApplicationStopping.Register(() => _cancellationTokenSource.Cancel());
    }


    internal IEndpointConventionBuilder Map(
        IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configure)
    {
        // TODO: EnableRequestDelegateGenerator does not work - how to do this right for AOT?
#warning HELP pretty please I tried, but EnableRequestDelegateGenerator defended me
#pragma warning disable IL3050
#pragma warning disable IL2026
        var conventionBuilder = endpoints.MapGet("_Tunnel/{clusterId}", TunnelWebSocketRouteGet);
#pragma warning restore IL3050
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

    private async Task<IResult> TunnelWebSocketRouteGet(HttpContext context, string? clusterId)
    {
        if (string.IsNullOrEmpty(clusterId))
        {
            return Results.BadRequest();
        }
        if (!context.WebSockets.IsWebSocketRequest)
        {
            return Results.BadRequest();
        }

        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
        if (!proxyConfigManager.TryGetCluster(clusterId, out var cluster))
        {
            Log.ClusterNotFound(_logger, clusterId);
            return Results.BadRequest();
        }

        if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(clusterId, out var tunnelConnectionChannels))
        {
            Log.TunnelConnectionChannelNotFound(_logger, clusterId);
            return Results.BadRequest();
        }
        if (_tunnelAuthenticationConfigService.CheckTunnelRequestIsAuthenticated(context, cluster))
        {
            return Results.StatusCode(401);
        }

        using (var ctsRequestAborted = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, _cancellationTokenSource.Token))
        {
            var channelTCRReader = tunnelConnectionChannels.Reader;
            _ = System.Threading.Interlocked.Increment(ref tunnelConnectionChannels.CountSource);
            try
            {
                var tunnelConnectionRequest = await channelTCRReader.ReadAsync(ctsRequestAborted.Token);
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
                                //await responsesWriter.WriteAsync(stream, ctsRequestAborted.Token);
                                if (tunnelConnectionRequest.Write(stream))
                                {
                                    _ = await stream.StreamCompleteTask;
                                    stream.Reset();
                                }

                                tunnelConnectionRequest = await channelTCRReader.ReadAsync(ctsRequestAborted.Token);
                            }
                        }
                    }
                }
            }
            finally
            {
                _ = System.Threading.Interlocked.Decrement(ref tunnelConnectionChannels.CountSource);
            }
        }

        return EmptyResult.Instance;
    }


    private void Dispose(bool disposing)
    {
        using (var unRegister = _unRegister)
        {
            if (disposing)
            {
                _unRegister = null;
            }
        }
    }

    ~TunnelWebSocketRoute()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
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
    }
}
