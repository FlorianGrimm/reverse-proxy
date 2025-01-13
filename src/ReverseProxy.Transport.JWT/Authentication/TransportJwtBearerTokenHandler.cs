// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
//using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Microsoft.IdentityModel.JsonWebTokens;

using Yarp.ReverseProxy.Tunnel;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transport;

namespace Yarp.ReverseProxy.Authentication;


/// <summary>
/// Handles JWT Bearer token authentication for transport.
/// </summary>
public class TransportJwtBearerTokenHandler
    : AuthenticationHandler<TransportJwtBearerTokenOptions>
    , IAuthenticationRequestHandler
{
#if NET8_0_OR_GREATER
    /// <summary>
    /// Initializes a new instance of the <see cref="TransportJwtBearerTokenHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public TransportJwtBearerTokenHandler(
        IOptionsMonitor<TransportJwtBearerTokenOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder
        )
        : base(options: options, logger: logger, encoder: encoder)
    {
        _logger = logger.CreateLogger<TransportJwtBearerTokenHandler>();
    }
#else
    /// <summary>
    /// Initializes a new instance of the <see cref="TransportJwtBearerTokenHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="clock">The system clock.</param>
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

    private readonly ILogger _logger;

    public async Task<bool> HandleRequestAsync()
    {
        try
        {
            var context = Context;
            var bearerToken = TransportJwtBearerUtility.GetBearerToken(context.Request.Headers.Authorization);
            if (bearerToken is null)
            {
                _logger.LogInformation("No bearer token");
                //return Task.FromResult(false);
                return false;
            }

            var transportJwtBearerTokenSigningCertificate = Context.RequestServices.GetRequiredService<TransportJwtBearerTokenSigningCertificate>();
            SecurityKey issuerSigningKey = transportJwtBearerTokenSigningCertificate.GetIssuerSigningKey();
            //TransportJwtBearerTokenHandler

            var jsonWebTokenHandler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();
            var jwtToken = jsonWebTokenHandler.ReadJsonWebToken(bearerToken);
            var tokenValidationResult = await jsonWebTokenHandler.ValidateTokenAsync(bearerToken, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidAudience = Options.Audience,
                ValidIssuers = Options.ValidIssuers,
                ValidateTokenReplay = true,
                IssuerSigningKey = issuerSigningKey
            });

            if (!tokenValidationResult.IsValid)
            {
            }
            var principal = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);
            //var jwtSecurityTokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            //var principal=jwtSecurityTokenHandler.ValidateToken(bearerToken, new TokenValidationParameters
            //{
            //    ValidateIssuer = true,
            //    ValidateAudience = true,
            //    ValidateLifetime = true,
            //    ValidateIssuerSigningKey = true,
            //    ValidIssuer = "", //jwtToken.Issuer,
            //    ValidIssuers = new[] { "" }, //jwtToken.ValidIssuers,
            //    ValidAudience = "", //jwtToken.Audience,
            //    ValidAudiences = new[] { "" }, //jwtToken.ValidAudiences,
            //    ValidateTokenReplay = true,
            //    IssuerSigningKey = issuerSigningKey
            //}, out var validatedToken);

            //Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler

            var jwtToken = new JwtSecurityToken(bearerToken);
            var issuer = ClaimsIssuer;
            var listClaims = new List<Claim>();
            listClaims.AddRange(jwtToken.Claims.Select(claim => new Claim(claim.Type, claim.Value, claim.ValueType, issuer)));
            var identity = new ClaimsIdentity(listClaims, issuer);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            var result = AuthenticateResult.Success(ticket);
            context.User = principal;
            var authFeatures = new YetAnotherAuthenticationFeatures(result);
            context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
            context.Features.Set<IAuthenticateResultFeature>(authFeatures);

            //return Task.FromResult(false);
            return false;
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed");
            //return Task.FromResult(false);
            return false;
        }
    }

    /// <summary>
    /// Handles the authentication process.
    /// </summary>
    /// <returns>The authentication result.</returns>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var context = Context;
            var bearerToken = TransportJwtBearerUtility.GetBearerToken(context.Request.Headers.Authorization);
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

}
