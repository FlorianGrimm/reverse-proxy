// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal abstract class TunnelAuthenticationBasic
    : ITunnelAuthenticationService
    , IDisposable
{
    private string _password = string.Empty;
    private readonly ILogger _logger;
    private IDisposable? _onChangeDisposable;

    protected TunnelAuthenticationBasic(
        IOptionsMonitor<TunnelAuthenticationBasicOptions> options,
        ILogger logger)
    {
        _logger = logger;
        _onChangeDisposable = options.OnChange(OptionsOnChange);
        OptionsOnChange(options.CurrentValue, default);
    }

    private void OptionsOnChange(TunnelAuthenticationBasicOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }
        if (options.Password is { Length: > 0 } plainPassword)
        {
            var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainPassword));
            var password = System.Convert.ToBase64String(hash);

            _password = $"Basic Tunnel:{password}";
        }
        else
        {
            _password = string.Empty;
        }
    }

    public string GetAuthenticationMode() => TunnelBasicConstants.AuthenticationMode;

    public abstract string GetTransport();

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions) { }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern) { }

    public ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        IResult? result;
        if (context.Request.Headers.Authorization is { } headerAuthorization
            && headerAuthorization.Count > 0
            && headerAuthorization[0] is { Length: > 0 } value
            && string.Equals(value, _password, System.StringComparison.Ordinal)
            )
        {
            result = null;
        }
        else
        {
            _logger.LogWarning("Unauthorized {Transport}:{ClusterId}", cluster.Model.Config.Transport, cluster.ClusterId);
            result = Microsoft.AspNetCore.Http.Results.Unauthorized();
        }
        return ValueTask.FromResult<IResult?>(result);
    }

    public void Dispose()
    {
        using (var onChangeUnlisten = _onChangeDisposable)
        {
            _onChangeDisposable = default;
        }
    }

    internal sealed class Http2 : TunnelAuthenticationBasic
    {
        public Http2(
            IOptionsMonitor<TunnelAuthenticationBasicOptions> options,
            ILogger<TunnelAuthenticationBasic.Http2> logger
            ) : base(
                options,
                logger
                )
        { }

        public override string GetTransport()
            => Yarp.ReverseProxy.Tunnel.TunnelConstants.TransportNameTunnelHTTP2;
    }

    internal sealed class WebSocket : TunnelAuthenticationBasic
    {
        public WebSocket(
            IOptionsMonitor<TunnelAuthenticationBasicOptions> options,
            ILogger<TunnelAuthenticationBasic.WebSocket> logger
            ) : base(
                options,
                logger
                )
        { }

        public override string GetTransport()
            => Yarp.ReverseProxy.Tunnel.TunnelConstants.TransportNameTunnelWebSocket;
    }
}
