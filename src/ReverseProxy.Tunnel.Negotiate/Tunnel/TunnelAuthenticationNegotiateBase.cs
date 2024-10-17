// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.FileSystemGlobbing.Internal;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// Enables or disables the Windows authentication for the tunnel.
/// A Windows account is required for the tunnel.
/// This might be useful for a corporate environment with firewall or inner VPNs.
/// You have to configure the authentication, e.g.
/// <code>
///     builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
///         .AddNegotiate();
/// </code>
/// </summary>

/*
    The Windows Authentication is not supported by the HTTP/2 protocol.
    The Windows Authentication is supported by the HTTP/1.1 protocol.
    So the authentication is done by the HTTP/1.1 protocol (and a cookie "YarpTunnelAuth" is set)
    and then the HTTP/2 protocol is used for the data (and the cookie is used for authn).
*/

internal class TunnelAuthenticationNegotiateBase
{
    public const string PolicyName = "YarpTunnelNegotiate";
    public const string AuthenticationName = "Negotiate";
    public const string CookieName = "YarpTunnelAuth";

    internal static void ConfigureAuthorizationPolicy(AuthorizationOptions options)
    {
        options.AddPolicy(
            PolicyName,
            policy => policy
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes(AuthenticationName)
            );
    }

    protected readonly ILogger _logger;

    public TunnelAuthenticationNegotiateBase(
        ILogger logger
        )
    {
        _logger = logger;
    }

    protected static class Log
    {
        private static readonly Action<ILogger, string, string, string, Exception?> _clusterAuthenticationSuccess = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.ClusterAuthenticationSuccess,
            "Cluster {clusterId} Authentication {AuthenticationName} success {subject}.");

        public static void ClusterAuthenticationSuccess(ILogger logger, string clusterId, string authenticationName, string subject)
        {
            _clusterAuthenticationSuccess(logger, clusterId, authenticationName, subject, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _clusterAuthenticationFailed = LoggerMessage.Define<string, string, string>(
            LogLevel.Information,
            EventIds.ClusterAuthenticationFailed,
            "Cluster {clusterId} Authentication {AuthenticationName} failed {subject}.");

        public static void ClusterAuthenticationFailed(ILogger logger, string clusterId, string authenticationName, string subject)
        {
            _clusterAuthenticationFailed(logger, clusterId, authenticationName, subject, null);
        }
    }
}
