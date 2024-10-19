using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Transforms;

namespace Yarp.ReverseProxy.Transport;

public class AuthenticationRequestTransform : RequestTransform
{
    private readonly AuthenticationTransformOptions _options;

    public AuthenticationRequestTransform(AuthenticationTransformOptions options)
    {
        _options = options;
    }

    public override ValueTask ApplyAsync(RequestTransformContext context)
    {
        //context.RequestTransforms.Add(new UserToJWTTransformModel());
        // AuthN and AuthZ will have already been completed after request routing.
        /*
                var ticket = await transformContext.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                var tokenService = transformContext.HttpContext.RequestServices.GetRequiredService<TokenService>();
                var token = await tokenService.GetAuthTokenAsync(ticket.Principal);

                // Reject invalid requests
                if (string.IsNullOrEmpty(token))
                {
                    var response = transformContext.HttpContext.Response;
                    response.StatusCode = 401;
                    return;
                }

                transformContext.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        context.ResponseTransforms.Add(new AffinitizeTransform(policy));
         */
        //
        var httpContext = context.HttpContext;
        var sourceUser = context.HttpContext.User;
        if (sourceUser is null)
        {
            return ValueTask.CompletedTask;
        }

        var destinationIdentity = new ClaimsIdentity();
        foreach (var sourceClaim in sourceUser.Claims)
        {
            if (_options.ExcludeClaimType.Contains(sourceClaim.Type))
            {
                continue;
            }
            if (_options.TransformClaimType.TryGetValue(sourceClaim.Type, out var destinationClaimType))
            {
                var destinationClaim = new Claim(type: destinationClaimType, value: sourceClaim.Value, valueType: sourceClaim.ValueType);
                destinationIdentity.AddClaim(destinationClaim);
            }
            else if (_options.IncludeClaimType.Contains(sourceClaim.Type))
            {
                var destinationClaim = new Claim(type: destinationClaimType, value: sourceClaim.Value, valueType: sourceClaim.ValueType);
                destinationIdentity.AddClaim(destinationClaim);
            }
        }

        Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler jwtHandler = new();
        

        var securityTokenHandler = _options.JwtSecurityTokenHandler ?? new();
        string? issuer = null;
        string? audience = null;
        string? authenticationType = null;
        var outboundClaims = new List<Claim>();

        var now = DateTime.UtcNow;
        DateTime? notBefore = now;
        DateTime? expires = now;
        DateTime? issuedAt = null;
        //RsaSecurityKey rsaSecurityKey = new RsaSecurityKey();
        var signingCredentials = new SigningCredentials(null!, null!);

        foreach (var claim in user.Claims)
        {
            if (securityTokenHandler.OutboundClaimTypeMap.TryGetValue(claim.Type, out var outboundClaimType))
            {
                var claimOutBound = new System.Security.Claims.Claim(outboundClaimType, claim.Value, issuer);
                outboundClaims.Add(claimOutBound);
            }
        }
        var outboundIdentity = new System.Security.Claims.ClaimsIdentity(claims: outboundClaims, authenticationType: authenticationType);

        var jwtSecurityToken = securityTokenHandler.CreateJwtSecurityToken(
            issuer: issuer,
            audience: audience,
            subject: new System.Security.Claims.ClaimsIdentity(user.Claims),
            notBefore: notBefore,
            expires: expires,
            issuedAt: issuedAt,
            signingCredentials: null);
        // jwtSecurityToken.ToString();
        //https://dev.to/eduardstefanescu/jwt-authentication-with-asymmetric-encryption-using-certificates-in-asp-net-core-2o7e
        // https://stackoverflow.com/questions/38794670/how-to-sign-a-jwt-using-rs256-with-rsa-private-key
        //https://gist.github.com/codeprefect/fd73d8f163cee82a0523721abe3aacd1
        //
        return default;
    }
}

