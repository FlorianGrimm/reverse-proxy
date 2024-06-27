// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Management;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelHTTP2Route : IDisposable
{
    private readonly UnShortCitcuitProxyConfigManager _proxyConfigManagerLazy;
    private readonly TunnelConnectionChannelManager _tunnelConnectionChannelManager;
    private readonly TunnelAuthenticationConfigService _tunnelAuthenticationConfigService;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger _logger;
    private CancellationTokenRegistration? _unRegister;
    private readonly CancellationTokenSource _cancellationTokenSource = new();

    public TunnelHTTP2Route(
        UnShortCitcuitProxyConfigManager proxyConfigManagerLazy,
        TunnelConnectionChannelManager tunnelConnectionChannelManager,
        TunnelAuthenticationConfigService tunnelAuthenticationConfigService,
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

    // [RequiresUnreferencedCode("")]
    internal IEndpointConventionBuilder Map(
        IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configure)
    {
        // TODO: EnableRequestDelegateGenerator does not work - how to do this right for AOT?
#warning HELP pretty please I tried, but EnableRequestDelegateGenerator defended me
#pragma warning disable IL3050
#pragma warning disable IL2026
        var conventionBuilder = endpoints.MapPost("_Tunnel/{clusterId}", TunnelHTTP2RoutePost);
#pragma warning restore IL3050
#pragma warning restore IL2026
        if (configure is not null)
        {
            configure(conventionBuilder);
        }
        return conventionBuilder;
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

        if (_tunnelAuthenticationConfigService.CheckTunnelRequestIsAuthenticated(context, cluster))
        {
            return Results.StatusCode(401);
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
                    using (var reg = ctsRequestAborted.Token.Register(() => stream.Abort()))
                    {
                        // Keep reusing this connection while, it's still open on the backend
                        while (!ctsRequestAborted.IsCancellationRequested)
                        {
                            // Make this connection available for requests
                            if (tunnelConnectionRequest.Write(stream))
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
