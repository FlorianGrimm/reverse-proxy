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
internal sealed class TunnelNegotiateWebSocket
    : TunnelNegotiateBase
    , ITunnelAuthenticationService
{
    public TunnelNegotiateWebSocket(
        ILogger<TunnelNegotiateWebSocket> logger
        ) : base(logger)
    {
    }

    public string GetAuthenticationMode() => TunnelNegotiateConstants.NegotiateAuthenticationName;

    public string GetTransport() => TunnelConstants.TransportNameTunnelWebSocket;

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
        conventionBuilder.RequireAuthorization(TunnelNegotiateConstants.PolicyNameGetAuth);
        conventionBuilder.WithMetadata(
            new TunnelAuthenticationScheme(
                Yarp.ReverseProxy.Tunnel.TunnelNegotiateConstants.NegotiateAuthenticationName));
    }

    public async ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        await Task.CompletedTask;
        return default;
    }
}
