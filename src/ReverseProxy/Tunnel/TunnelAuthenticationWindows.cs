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
    : ITunnelAuthenticationService
{
    private readonly ILogger<TunnelAuthenticationWindows> _logger;

    public TunnelAuthenticationWindows(
        ILogger<TunnelAuthenticationWindows> logger
        )
    {
        _logger = logger;
    }

    public string GetAuthenticationName() => "Windows";

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        // do nothing
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
#warning TODO Log
        if (context.User is not { } user)
        {
            _logger.LogDebug("TODO");
            return false;
        }
        if (user.Identity is not { } identity)
        {
            _logger.LogDebug("TODO");
            return false;
        }
        if (!identity.IsAuthenticated)
        {
            _logger.LogDebug("TODO");
            return false;
        }

        if (!string.Equals(user.Identity.AuthenticationType, "Negotiate", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug("TODO");
            return false;
        }

        var authentication = cluster.Model.Config.Authentication;
        var userNames = authentication.UserNames;
        if (userNames is null
            || userNames.Length == 0
            || (userNames.Length == 1 && string.Equals(userNames[0], "CurrentUser", StringComparison.OrdinalIgnoreCase)))
        {
            var envUserDomain = System.Environment.GetEnvironmentVariable("USERDOMAIN");
            var envUserName = System.Environment.GetEnvironmentVariable("USERNAME");
            var envUser = $"{envUserDomain}/{envUserName}";
            return string.Equals(identity.Name, envUser, StringComparison.OrdinalIgnoreCase);
        }
        return userNames.Contains(identity.Name);
    }
}

