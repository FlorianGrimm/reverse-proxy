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
using Yarp.ReverseProxy.Utilities;

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
            /*
            var context = Context;
            var bearerToken = TransportJwtBearerUtility.GetBearerToken(context.Request.Headers.Authorization);
            if (bearerToken is null)
            {
                _logger.LogInformation("No bearer token");
                return false;
            }

            var transportJwtBearerTokenSigningCertificate = Context.RequestServices.GetRequiredService<TransportJwtBearerTokenSigningCertificate>();
            var sharedIssuerSigningKey = transportJwtBearerTokenSigningCertificate.GetIssuerSigningKey();
            if (!(sharedIssuerSigningKey?.Value is { } issuerSigningKey))
            {
                _logger.LogError("No issuer signing key");
                return false;
            }

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
                _logger.LogError("Invalid token");
                return false;
            }

            var principal = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            var result = AuthenticateResult.Success(ticket);
            */
            var context = Context;
            var result = await this.HandleAuthenticateAsync();
            if (result.Principal is null)
            {
                return false;
            }

            context.User = result.Principal;
            var authFeatures = new YetAnotherAuthenticationFeatures(result);
            context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
            context.Features.Set<IAuthenticateResultFeature>(authFeatures);
            return true;
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
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var context = Context;
            var bearerToken = TransportJwtBearerUtility.GetBearerToken(context.Request.Headers.Authorization);
            if (bearerToken is null)
            {
                _logger.LogInformation("No bearer token");
                return AuthenticateResult.NoResult();
            }

            var transportJwtBearerTokenSigningCertificate = Context.RequestServices.GetRequiredService<TransportJwtBearerTokenSigningCertificate>();
            var sharedIssuerSigningKey = transportJwtBearerTokenSigningCertificate.GetIssuerSigningKey();
            if (!(sharedIssuerSigningKey?.Value is { } issuerSigningKey))
            {
                _logger.LogError("No issuer signing key");
                return AuthenticateResult.NoResult();
            }

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
                _logger.LogError("Invalid token");
                return AuthenticateResult.NoResult();
            }

            var principal = new ClaimsPrincipal(tokenValidationResult.ClaimsIdentity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed");
            return AuthenticateResult.NoResult();
        }
    }

}
