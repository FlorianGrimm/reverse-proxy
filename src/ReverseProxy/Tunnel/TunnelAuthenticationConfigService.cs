// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationConfigService
    : ITunnelAuthenticationConfigService
{
    private readonly List<ITunnelAuthenticationConfigService> _services;

    public TunnelAuthenticationConfigService(
        IEnumerable<ITunnelAuthenticationConfigService> listTunnelAuthenticationConfigService)
    {
        _services = listTunnelAuthenticationConfigService.ToList();
    }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        foreach (var service in _services)
        {
            service.ConfigureKestrelServer(kestrelServerOptions);
        }
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        foreach (var service in _services)
        {
            var result = service.CheckTunnelRequestIsAuthenticated(context, cluster);
            if (result) { return true; }
        }
        return false;
    }
}
