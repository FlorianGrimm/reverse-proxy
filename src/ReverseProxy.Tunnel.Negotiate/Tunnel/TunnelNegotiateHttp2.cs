// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Immutable;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
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

internal sealed class TunnelNegotiateHttp2
    : TunnelNegotiateBase
    , ITunnelAuthenticationService
    , ITunnelAuthenticationHandler
{
    private static readonly string[] AuthenticationTypes = ["NTLM", "Kerberos", "Kerberos2"];

    private readonly LazyProxyConfigManager _proxyConfigManagerLazy;
    private readonly ITunnelAuthenticationCookieService _cookieService;

    public TunnelNegotiateHttp2(
        LazyProxyConfigManager proxyConfigManagerLazy,
        ITunnelAuthenticationCookieService cookieService,
        ILogger<TunnelNegotiateHttp2> logger
        ) : base(logger)
    {
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _cookieService = cookieService;
    }

    public string GetAuthenticationMode() => TunnelNegotiateConstants.NegotiateAuthenticationName;

    public string GetTransport() => TunnelConstants.TransportNameTunnelHTTP2;

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="endpoints"></param>
    /// <param name="conventionBuilder"></param>
    /// <param name="pattern"></param>
    /// <remarks>
    /// <see cref="TunnelNegotiateBase.ConfigureAuthorizationPolicy(Microsoft.AspNetCore.Authorization.AuthorizationOptions)"/>
    /// </remarks>
    public void MapAuthentication(
        IEndpointRouteBuilder endpoints,
        RouteHandlerBuilder conventionBuilder,
        string pattern)
    {
        // will use HTTP1 and Negotiate
        var endpointMapGet = endpoints.MapGet(pattern, MapGetAuth);
        endpointMapGet.RequireAuthorization(TunnelNegotiateConstants.PolicyNameGetAuth);
        endpointMapGet.WithMetadata(
            new TunnelAuthenticationSchemeMetadata(
                Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme),
            new TunnelAuthenticationMetadata(this));

        // will use
        conventionBuilder.RequireAuthorization(TunnelNegotiateConstants.PolicyNamePayload);
        conventionBuilder
            .WithMetadata(
                new TunnelAuthenticationSchemeMetadata(
                    Yarp.ReverseProxy.Tunnel.TunnelAuthenticationDefaults.AuthenticationScheme),
                new TunnelAuthenticationMetadata(this));
    }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
    }

    public ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (context.Request.Cookies.TryGetValue(TunnelNegotiateConstants.CookieName, out var auth)
            && auth is { Length: > 0 }
            && _cookieService.ValidateCookie(auth, out var principal)
            && principal.Identity?.Name is { Length: > 0 } identityName
            && IsIdentityValid(identityName, cluster.Model.Config.TransportAuthentication)
            )
        {
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, identityName);
            return ValueTask.FromResult<IResult?>(default);
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "no YarpTunnelAuth");
            return ValueTask.FromResult<IResult?>(Results.StatusCode(401));
        }
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
            && cluster.Model.Config.IsTunnelTransport()
            && IsWindowsAuthenticated(context, cluster)
            )
        {
            context.Response.StatusCode = 200;

            ClaimsPrincipal principal = new(new ClaimsIdentity(((ClaimsIdentity)identity).Claims, identity.AuthenticationType));
            var auth = _cookieService.NewCookie(principal);
            context.Response.Cookies.Append(TunnelNegotiateConstants.CookieName, auth, new CookieOptions()
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
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "no User");
            return false;
        }
        if (user.Identity is not { } identity)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "no Identity");
            return false;
        }
        if (!identity.IsAuthenticated)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "not IsAuthenticated");
            return false;
        }
        if (!AuthenticationTypes.Contains(user.Identity.AuthenticationType, StringComparer.OrdinalIgnoreCase))
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "not Negotiate");
            return false;
        }

        var identityName = identity.Name ?? string.Empty;
        var authentication = cluster.Model.Config.TransportAuthentication;
        var result = IsIdentityValid(identityName, authentication);
        if (result)
        {
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, identityName);
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, identityName);
        }
        return result;
    }

    // Checks if the identity the one that is configured.
    private static bool IsIdentityValid(string identityName, ClusterTunnelAuthenticationConfig authentication)
    {
        if (string.IsNullOrEmpty(identityName))
        {
            return false;
        }
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


    // ITunnelAuthentication

    public ValueTask<TunnelAuthenticationResponse> HandleTunnelAuthenticateAsync(
        HttpContext context,
        ClusterConfig clusterConfig,
        string scheme,
        string claimsIssuer)
    {
        if (!(context.Request.Cookies.TryGetValue(TunnelNegotiateConstants.CookieName, out var auth)))
        {
            Log.ClusterAuthenticationFailed(_logger, clusterConfig.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "YarpTunnelAuth Cookie not found");
            return new(new TunnelAuthenticationResponse(AuthenticateResult.NoResult()));
        }

        if (!(auth is { Length: > 0 }
            && _cookieService.ValidateCookie(auth, out var principal)
            && principal is { }
           ))
        {
            Log.ClusterAuthenticationFailed(_logger, clusterConfig.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "principal invalid.");
            return new(new TunnelAuthenticationResponse(AuthenticateResult.NoResult()));
        }

        if (!(principal.Identity?.Name is { Length: > 0 } identityName
            && IsIdentityValid(identityName, clusterConfig.TransportAuthentication)
           ))
        {
            Log.ClusterAuthenticationFailed(_logger, clusterConfig.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, "Identity invalid.");
            return new(new TunnelAuthenticationResponse(AuthenticateResult.NoResult()));
        }

        Log.ClusterAuthenticationSuccess(_logger, clusterConfig.ClusterId, TunnelNegotiateConstants.NegotiateAuthenticationName, identityName);
        var ticket = new AuthenticationTicket(principal!, scheme);
        return new(new TunnelAuthenticationResponse(AuthenticateResult.Success(ticket)));
    }
}
