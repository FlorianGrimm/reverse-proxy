// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;
internal sealed class TunnelAuthenticationNegotiateWebSocket
    : TunnelAuthenticationNegotiateBase
    , ITunnelAuthenticationService
{
    public TunnelAuthenticationNegotiateWebSocket(
        ILogger<TunnelAuthenticationNegotiateWebSocket> logger
        ) : base(logger)
    {
    }

    public string GetAuthenticationMode() => TunnelNegotiateConstants.AuthenticationName;

    public string GetTransport() => TunnelConstants.TransportNameTunnelWebSocket;

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
        conventionBuilder.RequireAuthorization(TunnelNegotiateConstants.PolicyNameGetAuth);
    }

    public async ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        await Task.CompletedTask;
        return default;
    }
}
