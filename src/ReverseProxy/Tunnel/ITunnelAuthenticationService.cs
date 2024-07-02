// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

public interface ITunnelAuthenticationService
{
    void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions);

    bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster);
    string GetAuthenticationName();
}
