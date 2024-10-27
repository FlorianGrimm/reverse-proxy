using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;

using Yarp.ReverseProxy.Transforms;


namespace Yarp.ReverseProxy.Transport;

public class AuthenticationTransportRequestTransform : RequestTransform
{
    private const string Authorization = "Authorization";

    private readonly AuthorizationTransportOptions _options;
    private readonly AuthenticationTransportSigningCertificate _signingCertificate;

    public AuthenticationTransportRequestTransform(
        AuthorizationTransportOptions options,
        AuthenticationTransportSigningCertificate signingCertificate)
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
                    return;
                }
            }
        }

        using var shareSigningCertificate = _signingCertificate.GetCertificate();
        if (shareSigningCertificate is null
            || shareSigningCertificate.Value is not { Count:>0} collection
            || collection[0] is not X509Certificate2 signingCertificate2)
        {
            return;
        }

        var httpContext = context.HttpContext;
        var sourceUser = context.HttpContext.User;
        if (sourceUser is null
            || sourceUser.Identity is null
            || sourceUser.Identity.IsAuthenticated
            )
        {

            var ticket = await httpContext.AuthenticateAsync(_options.Scheme);
            if (ticket.Succeeded && ticket.Principal is { } principal)
            {
                sourceUser = principal;
            }
        }
        if (sourceUser is null) { return; }

        var outboundClaimsIdentity = new ClaimsIdentity();
        foreach (var sourceClaim in sourceUser.Claims)
        {
            if (_options.ExcludeClaimType.Contains(sourceClaim.Type))
            {
                continue;
            }
            if (_options.TransformClaimType.TryGetValue(sourceClaim.Type, out var destinationClaimType))
            {
                var outboundClaim = new Claim(type: destinationClaimType, value: sourceClaim.Value, valueType: sourceClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            }
            else if (_options.IncludeClaimType.Contains(sourceClaim.Type))
            {
                var outboundClaim = new Claim(type: sourceClaim.Type, value: sourceClaim.Value, valueType: sourceClaim.ValueType);
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
            NotBefore = now.Add(_options.NotBefore),
            Expires = now.Add(_options.Expires),
            Subject = outboundClaimsIdentity,
            SigningCredentials = signingCredentials
        };

        Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler jsonWebTokenHandler = new();

        var jwtToken = jsonWebTokenHandler.CreateToken(descriptor);
        
        context.ProxyRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

        // https://dev.to/eduardstefanescu/jwt-authentication-with-asymmetric-encryption-using-certificates-in-asp-net-core-2o7e
        // https://stackoverflow.com/questions/38794670/how-to-sign-a-jwt-using-rs256-with-rsa-private-key
        // https://gist.github.com/codeprefect/fd73d8f163cee82a0523721abe3aacd1
        
        return;
    }
}

