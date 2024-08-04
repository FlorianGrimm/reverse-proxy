// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed partial class TunnelHTTP2Route : IDisposable
{
    private readonly ILazyRequiredServiceResolver<IProxyStateLookup> _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly TunnelAuthenticationService _tunnelAuthenticationConfigService;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger _logger;
    private CancellationTokenRegistration? _unRegister;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    public TunnelHTTP2Route(
        ILazyRequiredServiceResolver<IProxyStateLookup> proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        TunnelAuthenticationService tunnelAuthenticationConfigService,
        IHostApplicationLifetime lifetime,
        ILogger<TunnelHTTP2Route> logger)
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
            var authenticationName = tunnelAuthentication.GetAuthenticationName();

            var pattern = $"_Tunnel/H2/{authenticationName}/{{clusterId}}";
            var conventionBuilder = endpoints.MapPost(pattern, TunnelHTTP2RoutePost);
#if NET8_0_OR_GREATER
            conventionBuilder.WithHttpLogging(Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.RequestHeaders|Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.RequestPath);
#endif
            if (configure is not null)
            {
                configure(conventionBuilder);
            }
            tunnelAuthentication.MapAuthentication(endpoints, conventionBuilder, pattern);
        }
    }

    private async Task<IResult> TunnelHTTP2RoutePost(HttpContext context, string? clusterId)
    {
        if (string.IsNullOrEmpty(clusterId))
        {
            return Results.BadRequest();
        }
        // HTTP/2 duplex stream
        if (context.Request.Protocol != HttpProtocol.Http2)
        {
            return Results.BadRequest();
        }

        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
        if (!proxyConfigManager.TryGetCluster(clusterId, out var cluster))
        {
            Log.ClusterNotFound(_logger, clusterId);
            return Results.StatusCode(504);
        }

        if (!_tunnelConnectionChannelManager.TryGetConnectionChannel(clusterId, out var tunnelConnectionChannels))
        {
            Log.TunnelConnectionChannelNotFound(_logger, clusterId);
            return Results.StatusCode(504);
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

            System.Threading.Interlocked.Increment(ref tunnelConnectionChannels.CountSource);
            TunnelConnectionRequest? tunnelConnectionRequest = null;
            try
            {
                try
                {
                    tunnelConnectionRequest = await channelTCRReader.ReadAsync(ctsRequestAborted.Token);
                }
                catch (System.OperationCanceledException)
                {
                    return EmptyResult.Instance;
                }

                if (ctsRequestAborted.IsCancellationRequested)
                {
                    return EmptyResult.Instance;
                }

                using (var stream = new TunnelDuplexHttpStream(context))
                {
                    using (var reg = ctsRequestAborted.Token.Register(() =>
                    {
                        _logger.LogDebug("Tunnel connection aborted");
                        stream.Abort();
                    }))
                    {
                        // Keep reusing this connection while, it's still open on the backend
                        while (!ctsRequestAborted.IsCancellationRequested)
                        {
                            // Make this connection available for requests
                            if (tunnelConnectionRequest.SetStream(stream))
                            {
                                await stream.StreamCompleteTask.ConfigureAwait(false);
                                stream.Reset();
                            }

                            tunnelConnectionRequest = null;
                            try
                            {
                                tunnelConnectionRequest = await channelTCRReader.ReadAsync(ctsRequestAborted.Token);
                            }
                            catch (System.OperationCanceledException)
                            {
                                return EmptyResult.Instance;
                            }
                            if (ctsRequestAborted.IsCancellationRequested)
                            {
                                return EmptyResult.Instance;
                            }

                        }
                    }
                }
            }
            catch (Exception error)
            {
                _logger.LogError(error, "Error in TunnelHTTP2RoutePost");
                return Results.StatusCode(504);
            }
            finally
            {
                System.Threading.Interlocked.Decrement(ref tunnelConnectionChannels.CountSource);
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

    ~TunnelHTTP2Route()
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
