// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelWebSocketRoute
    : IDisposable
{
    private readonly ILazyRequiredServiceResolver<IProxyStateLookup> _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly TunnelAuthenticationService _tunnelAuthenticationConfigService;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger _logger;
    private CancellationTokenRegistration? _unRegister;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    public TunnelWebSocketRoute(
        ILazyRequiredServiceResolver<IProxyStateLookup> proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        TunnelAuthenticationService tunnelAuthenticationConfigService,
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

    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    internal void Map(
        IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configure)
    {
        var tunnelAuthenticationService = endpoints.ServiceProvider.GetRequiredService<TunnelAuthenticationService>();
        foreach (var tunnelAuthentication in tunnelAuthenticationService.GetTunnelAuthenticationServices())
        {
            var authenticationName =  tunnelAuthentication.GetAuthenticationName();
            var pattern = $"_Tunnel/WS/{authenticationName}/{{clusterId}}";
            var conventionBuilder = endpoints.MapGet(pattern, TunnelWebSocketRouteGet);

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
            tunnelAuthentication.MapAuthentication(endpoints, conventionBuilder, pattern);

        }
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
        var result = _tunnelAuthenticationConfigService.CheckTunnelRequestIsAuthenticated(context, cluster);
        if (result is { })
        {
            // return Results.Challenge(); does not work if you have more than one and the tunnel auth is not the default/challange one
            return result;
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
                                if (tunnelConnectionRequest.SetStream(stream))
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
