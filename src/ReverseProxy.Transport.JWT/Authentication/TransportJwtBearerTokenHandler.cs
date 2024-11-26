// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Authentication;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Authentication;

public class TransportJwtBearerTokenHandler
    //: RemoteAuthenticationHandler<TransportJwtBearerTokenOptions>
    : AuthenticationHandler<TransportJwtBearerTokenOptions>
// IAuthenticationHandlerProvider
{
#if NET8_0_OR_GREATER
    public TransportJwtBearerTokenHandler(
        IOptionsMonitor<TransportJwtBearerTokenOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder
        )
        : base(options: options, logger: logger, encoder: encoder)
    {
        _logger = logger.CreateLogger<TransportJwtBearerTokenHandler>();
    }
#endif

#if NET6_0 || NET7_0
    //[Obsolete("ISystemClock is obsolete, use TimeProvider on AuthenticationSchemeOptions instead.")]
    public TransportJwtBearerTokenHandler(
        IOptionsMonitor<TransportJwtBearerTokenOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock
        )
        : base(options, logger, encoder, clock)
    {
        _logger = logger.CreateLogger<TransportJwtBearerTokenHandler>();
    }

#endif

    private readonly ILogger<TransportJwtBearerTokenHandler> _logger;

    protected override Task InitializeEventsAsync()
    {
        return base.InitializeEventsAsync();
    }
    protected override Task InitializeHandlerAsync()
    {
        return base.InitializeHandlerAsync();
    }
    protected override string? ResolveTarget(string? scheme)
    {
        return base.ResolveTarget(scheme);
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var context = Context;
            var bearerToken = TransportJwtBearerTokenExtensions.GetBearerToken(context.Request.Headers.Authorization);
            if (bearerToken is null)
            {
                _logger.LogInformation("No bearer token");
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var jwtToken = new JwtSecurityToken(bearerToken);

            var issuer = ClaimsIssuer;
            var listClaims = new List<Claim>();
            listClaims.AddRange(jwtToken.Claims.Select(claim => new Claim(claim.Type, claim.Value, claim.ValueType, issuer)));
            var identity = new ClaimsIdentity(listClaims, issuer);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed");
            return Task.FromResult(AuthenticateResult.NoResult());
        }
    }



#if no
    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var context = Context;
        string? bearerToken = default;
        foreach (var valueAuthorization in context.Request.Headers.Authorization)
        {
            if (valueAuthorization is { Length: > 7 }
                && valueAuthorization.StartsWith(Prefix))
            {
                bearerToken = valueAuthorization.Substring(Prefix.Length);
            }
        }
        if (bearerToken is null)
        {
            return HandleRequestResult.NoResult();
        }
        await Task.CompletedTask;

        var jwtToken = new JwtSecurityToken(bearerToken);

        var listClaims = new List<Claim>();
        listClaims.AddRange(jwtToken.Claims);
        var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    listClaims));
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return HandleRequestResult.Success(ticket);
    }
#endif
}
