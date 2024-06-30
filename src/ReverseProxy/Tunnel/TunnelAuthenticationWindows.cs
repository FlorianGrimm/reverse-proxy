// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationWindows
    : ITunnelAuthenticationConfigService
{
    private readonly ILogger<TunnelAuthenticationWindows> _logger;

    public TunnelAuthenticationWindows(
        ILogger<TunnelAuthenticationWindows> logger
        )
    {
        _logger = logger;
    }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        // do nothing
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (!string.Equals(cluster.Model.Config.Authentication.Mode, "Windows", System.StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (context.User is not { } user) { return false; }
        if (user.Identity is not { } identity) { return false; }

        _logger.LogInformation("AuthenticationType: {AuthenticationType}", user.Identity.AuthenticationType);
        if (!string.Equals(user.Identity.AuthenticationType, "Negotiate", StringComparison.OrdinalIgnoreCase)) { return false; }
        if (cluster.Model.Config.Authentication.UserNames is not { } userNames) { return false; }
        return userNames.Contains(identity.Name);
    }
}

