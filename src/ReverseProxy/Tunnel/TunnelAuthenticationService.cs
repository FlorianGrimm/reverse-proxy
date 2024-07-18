// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationService
    : ITunnelAuthenticationService
{
    private readonly List<ITunnelAuthenticationService> _services;
    private readonly ImmutableDictionary<string, ITunnelAuthenticationService> _servicesByAuthenticationName;

    public TunnelAuthenticationService(
        IEnumerable<ITunnelAuthenticationService> listTunnelAuthenticationConfigService)
    {
        _services = listTunnelAuthenticationConfigService.ToList();
        _servicesByAuthenticationName = _services.ToImmutableDictionary(service => service.GetAuthenticationName(), StringComparer.OrdinalIgnoreCase);
    }

    public string GetAuthenticationName() { throw new NotSupportedException(); }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        foreach (var service in _services)
        {
            service.ConfigureKestrelServer(kestrelServerOptions);
        }
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
        throw new NotSupportedException("call the real ITunnelAuthenticationService - service.");
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (cluster.Model.Config.Authentication.Mode is { Length: > 0 } mode
            && _servicesByAuthenticationName.TryGetValue(mode, out var service))
        {
            return service.CheckTunnelRequestIsAuthenticated(context, cluster);
        }
        else
        {
            return false;
        }
    }

    internal IReadOnlyCollection<ITunnelAuthenticationService> GetTunnelAuthenticationServices()
        => _services.AsReadOnly();
}
