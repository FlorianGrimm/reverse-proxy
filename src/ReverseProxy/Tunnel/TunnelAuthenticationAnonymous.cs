// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationAnonymous
    : ITunnelAuthenticationService
{
    public TunnelAuthenticationAnonymous() { }

    public string GetAuthenticationName() => "Anonymous";

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions) { }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern) { }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster) => true;
}

