// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationAnonymous
    : ITunnelAuthenticationService
{
    public TunnelAuthenticationAnonymous() { }

    public string GetAuthenticationName() => "Anonymous";

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        // do nothing
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        return true;
    }
}

