// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal class TunnelAuthenticationAnonymous
    : ITunnelAuthenticationService
{
    internal sealed class WebSocket : TunnelAuthenticationAnonymous
    {
        public WebSocket() : base("TunnelWebSocket") { }
    }

    internal sealed class Http2 : TunnelAuthenticationAnonymous
    {
        public Http2() : base("TunnelHTTP2") { }
    }

    private readonly string _transport;

    protected TunnelAuthenticationAnonymous(string transport)
    {
        _transport = transport;
    }

    public string GetAuthenticationMode() => "Anonymous";

    public string GetTransport() => _transport;

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions) { }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern) { }

    public ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
        => ValueTask.FromResult<IResult?>(default);

}

