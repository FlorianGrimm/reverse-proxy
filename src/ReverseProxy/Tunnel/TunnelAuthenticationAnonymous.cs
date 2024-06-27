// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal class TunnelAuthenticationAnonymous
    : ITunnelAuthenticationConfigService
{
    public TunnelAuthenticationAnonymous()
    {
    }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        // do nothing
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (!string.Equals(cluster.Model.Config.Authentication.Mode, "Anonymous", StringComparison.InvariantCultureIgnoreCase))
        {
            return false;
        }
        return true;

    }
}

