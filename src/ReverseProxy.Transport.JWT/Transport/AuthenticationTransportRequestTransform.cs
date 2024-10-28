using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Transforms;


namespace Yarp.ReverseProxy.Transport;

internal class AuthorizationTransportRequestTransform : RequestTransform
{
    private const string Authorization = "Authorization";
    private const string WWWAuthenticate = "WWW-Authenticate";

    private readonly AuthorizationTransportOptions _options;
    private readonly AuthorizationTransportSigningCertificate _signingCertificate;

    internal AuthorizationTransportRequestTransform(
        AuthorizationTransportOptions options,
        AuthorizationTransportSigningCertificate signingCertificate)
    {
        _options = options;
        _signingCertificate = signingCertificate;
    }

    public override async ValueTask ApplyAsync(RequestTransformContext context)
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
        if (_options.DoNotModifyAuthorizationIfBaerer)
        {
            if (context.ProxyRequest.Headers.Authorization is { } authorization)
            {
                if (string.Equals(authorization.Scheme, "Baerer"))
                {
                    if (_options.RemoveHeaderAuthenticate)
                    {
                        context.ProxyRequest.Headers.Remove(WWWAuthenticate);
                    }
                    return;
                }
            }
        }

        using var shareSigningCertificate = _signingCertificate.GetCertificate();
        if (shareSigningCertificate is null
            || shareSigningCertificate.Value is not { Count: > 0 } collection
            || collection[0] is not X509Certificate2 signingCertificate2)
        {
            return;
        }

        var httpContext = context.HttpContext;

        // their must be an inboundUser
        ClaimsPrincipal inboundUser;
        {
            var contextUser = context.HttpContext.User;

            if (contextUser.Identity is null
                || contextUser.Identity.IsAuthenticated)
            {
                var ticket = await httpContext.AuthenticateAsync(_options.Scheme);
                if (ticket is { Succeeded: true, Principal: { } principal })
                {
                    inboundUser = principal;
                }
                else
                {
                    if (_options.RemoveHeaderAuthenticate)
                    {
                        context.ProxyRequest.Headers.Remove(WWWAuthenticate);
                        context.ProxyRequest.Headers.Remove(Authorization);
                    }
                    return;
                }
            }
            else
            {
                inboundUser = contextUser;
            }
        }

        var outboundClaimsIdentity = new ClaimsIdentity();
        foreach (var inboundClaim in inboundUser.Claims)
        {
            if (_options.ExcludeClaimType.Contains(inboundClaim.Type))
            {
                continue;
            }

            if (_options.TransformClaimType.TryGetValue(inboundClaim.Type, out var destinationClaimType))
            {
                var outboundClaim = new Claim(type: destinationClaimType, value: inboundClaim.Value,
                    valueType: inboundClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            }
            else if (_options.IncludeClaimType.Contains(inboundClaim.Type))
            {
                var outboundClaim = new Claim(type: inboundClaim.Type, value: inboundClaim.Value,
                    valueType: inboundClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            }
        }

        X509SecurityKey securityKey = new(signingCertificate2);
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now,
            NotBefore = now.Add(_options.AdjustNotBefore),
            Expires = now.Add(_options.AdjustExpires),
            Subject = outboundClaimsIdentity,
            SigningCredentials = signingCredentials
        };

        Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler jsonWebTokenHandler = new();

        var jwtToken = jsonWebTokenHandler.CreateToken(descriptor);

        context.ProxyRequest.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

        if (_options.RemoveHeaderAuthenticate) {
            context.ProxyRequest.Headers.Remove(WWWAuthenticate);            
        }

        // https://dev.to/eduardstefanescu/jwt-authentication-with-asymmetric-encryption-using-certificates-in-asp-net-core-2o7e
        // https://stackoverflow.com/questions/38794670/how-to-sign-a-jwt-using-rs256-with-rsa-private-key
        // https://gist.github.com/codeprefect/fd73d8f163cee82a0523721abe3aacd1

        return;
    }
}
