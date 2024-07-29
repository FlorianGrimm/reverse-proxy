// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;

/*
    The Windows Authentication is not supported by the HTTP/2 protocol.
    The Windows Authentication is supported by the HTTP/1.1 protocol.
    So the authentication is done by the HTTP/1.1 protocol (and a cookie "YarpTunnelAuth" is set)
    and then the HTTP/2 protocol is used for the data (and the cookie is used for authn).
*/
internal sealed class TunnelAuthenticationWindows
    : ITunnelAuthenticationService
{
    public const string PolicyName = "YarpTunnelWindows";

    internal static void ConfigureAuthorizationPolicy(AuthorizationOptions options)
    {
        options.AddPolicy(
            PolicyName,
            policy => policy
                .RequireAuthenticatedUser()
                .AddAuthenticationSchemes("Negotiate")
            );
    }

    public const string AuthenticationName = "Windows";
    public const string CookieName = "YarpTunnelAuth";
    private static readonly string[] AuthenticationTypes = ["NTLM", "Kerberos", "Kerberos2"];
    private readonly ILazyRequiredServiceResolver<ProxyConfigManager> _proxyConfigManagerLazy;
    private readonly ITunnelAuthenticationCookieService _cookieService;
    private readonly ILogger _logger;

    public TunnelAuthenticationWindows(
        ILazyRequiredServiceResolver<ProxyConfigManager> proxyConfigManagerLazy,
        ITunnelAuthenticationCookieService cookieService,
        ILogger<TunnelAuthenticationWindows> logger
        )
    {
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _cookieService = cookieService;
        _logger = logger;
    }

    public string GetAuthenticationName() => AuthenticationName;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        // do nothing
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
        // add a second endpoint for the same pattern but for GET not POST.
        endpoints.MapGet(pattern, MapGetAuth).RequireAuthorization(PolicyName);
    }

    /*
        Get and validate the Windows authenticated User
        and add cookie "YarpTunnelAuth" in the response.
     */
    private async Task MapGetAuth(HttpContext context)
    {
        var identity = context.User.Identity;
        if (identity is { IsAuthenticated: true }
            && identity.Name is { Length: > 0 } name
            && AuthenticationTypes.Contains(identity.AuthenticationType, StringComparer.OrdinalIgnoreCase)
            && context.GetRouteValue("clusterId") is string clusterId
            && _proxyConfigManagerLazy.GetService().TryGetCluster(clusterId, out var cluster)
            && cluster.Model.Config.IsTunnelTransport
            && IsWindowsAuthenticated(context, cluster)
            )
        {
            context.Response.StatusCode = 200;

            ClaimsPrincipal principal = new(new ClaimsIdentity(((ClaimsIdentity)identity).Claims, identity.AuthenticationType));
            var auth = _cookieService.NewCookie(principal);
            context.Response.Cookies.Append(CookieName, auth, new CookieOptions()
            {
                Domain = context.Request.Host.Host,
                Path = context.Request.Path,
                IsEssential = true,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict
            });
            await context.Response.WriteAsync("OK");
        }
        else
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
        }
        await context.Response.CompleteAsync();
    }

    /// <summary>
    /// Check if the outer tunnel request is authenticated.
    /// This checks the cookie "YarpTunnelAuth" in the request.
    /// </summary>
    /// <param name="context">http</param>
    /// <param name="cluster">current cluster</param>
    /// <returns>true ok - false 401 response.</returns>
    public IResult? CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (context.Request.Cookies.TryGetValue(CookieName, out var auth)
            && auth is { Length: > 0 }
            && _cookieService.ValidateCookie(auth, out var principal)
            && principal.Identity?.Name is { Length: > 0 } identityName
            && IsIdentityValid(identityName, cluster.Model.Config.Authentication)
            )
        {
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, AuthenticationName, identityName);
            return default;
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "no YarpTunnelAuth");
            //return Results.Challenge(null, ["Negotiate"]);
            return Results.StatusCode(401);
        }
    }

    /// <summary>
    /// Checks if the Windows authenticated User is valid.
    /// Used to check the first GET request.
    /// </summary>
    /// <param name="context">context</param>
    /// <param name="cluster">cluster</param>
    /// <returns>true ok - false 401 response.</returns>
    private bool IsWindowsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (context.User is not { } user)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "no User");
            return false;
        }
        if (user.Identity is not { } identity)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "no Identity");
            return false;
        }
        if (!identity.IsAuthenticated)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "not IsAuthenticated");
            return false;
        }
        if (!AuthenticationTypes.Contains(user.Identity.AuthenticationType, StringComparer.OrdinalIgnoreCase))
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "not Negotiate");
            return false;
        }

        var identityName = identity.Name ?? string.Empty;
        var authentication = cluster.Model.Config.Authentication;
        var result = IsIdentityValid(identityName, authentication);
        if (result)
        {
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, AuthenticationName, identityName);
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, identityName);
        }
        return result;
    }

    // Checks if the identity the one that is configured.
    private static bool IsIdentityValid(string identityName, ClusterTunnelAuthenticationConfig authentication)
    {
        var userNames = authentication.UserNames;

        bool result;

        if (userNames is null
            || userNames.Length == 0
            || (userNames.Length == 1 && string.Equals(userNames[0], "CurrentUser", StringComparison.OrdinalIgnoreCase)))
        {
            var envUserDomain = System.Environment.GetEnvironmentVariable("USERDOMAIN");
            var envUserName = System.Environment.GetEnvironmentVariable("USERNAME");
            var envUser = $"{envUserDomain}\\{envUserName}";
            result = string.Equals(identityName, envUser, StringComparison.OrdinalIgnoreCase);
        }
        else
        {
            result = userNames.Contains(identityName);
        }

        return result;
    }

    private static class Log
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
