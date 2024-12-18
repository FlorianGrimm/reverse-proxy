using System;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Transforms;

namespace Yarp.ReverseProxy.Transport;

internal sealed class AuthorizationTransportRequestTransform : RequestTransform
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
        if (_options.DoNotModifyAuthorizationIfBearer)
        {
            if (context.ProxyRequest.Headers.Authorization is { } authorization)
            {
                if (string.Equals(authorization.Scheme, "Bearer"))
                {
                    if (_options.RemoveHeaderAuthenticate)
                    {
                        context.ProxyRequest.Headers.Remove(WWWAuthenticate);
                    }
                    return;
                }
            }
        }

        using (var shareSigningCredentials = _signingCertificate.GetSigningCredentials())
        {
            if (shareSigningCredentials is null
                || shareSigningCredentials.Value is not { } signingCredentials)
            {
                if (_options.RemoveHeaderAuthenticate)
                {
                    context.ProxyRequest.Headers.Remove(Authorization);
                    context.ProxyRequest.Headers.Remove(WWWAuthenticate);
                }
                return;
            }

            var httpContext = context.HttpContext;
            ClaimsPrincipal? inboundUser;
            {
                var contextUser = context.HttpContext.User;

                if (contextUser.Identity is null
                    || !contextUser.Identity.IsAuthenticated)
                {
                    string? scheme=null;
                    if (_options.AuthenticationSchemeSelector is { } schemeSelector) {
                        scheme = schemeSelector(httpContext);
                    }
                    scheme ??= _options.Scheme;

                    var ticket = await httpContext.AuthenticateAsync(scheme);
                    if (ticket is { Succeeded: true, Principal: { } principal })
                    {
                        inboundUser = principal;
                    }
                    else
                    {
                        inboundUser = default;
                    }
                }
                else
                {
                    inboundUser = contextUser;
                }
            }

            if (inboundUser is { }
                && inboundUser.Identity is { } identity
                && identity.IsAuthenticated)
            {
                var outboundClaimsIdentity = new ClaimsIdentity();

                var includeAll = _options.IncludeClaimType.Contains("ALL")
                    || ((_options.ExcludeClaimType.Count == 0)
                        && (_options.TransformClaimType.Count == 0)
                        && (_options.IncludeClaimType.Count == 0)
                        );
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
                    else if (includeAll || _options.IncludeClaimType.Contains(inboundClaim.Type))
                    {
                        var outboundClaim = new Claim(type: inboundClaim.Type, value: inboundClaim.Value,
                            valueType: inboundClaim.ValueType);
                        outboundClaimsIdentity.AddClaim(outboundClaim);
                    }
                }

                if (outboundClaimsIdentity.Claims.Any())
                {
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

                    //if (_options.RemoveHeaderAuthenticate)
                    //{
                    context.ProxyRequest.Headers.Remove(WWWAuthenticate);
                    //}

                    // https://dev.to/eduardstefanescu/jwt-authentication-with-asymmetric-encryption-using-certificates-in-asp-net-core-2o7e
                    // https://stackoverflow.com/questions/38794670/how-to-sign-a-jwt-using-rs256-with-rsa-private-key

                    // https://gist.github.com/codeprefect/fd73d8f163cee82a0523721abe3aacd1
                    return;
                }
            }
        }

        if (_options.RemoveHeaderAuthenticate)
        {
            context.ProxyRequest.Headers.Remove(WWWAuthenticate);
            context.ProxyRequest.Headers.Remove(Authorization);
        }

        return;
    }
}



internal sealed class AuthorizationTransportResponseTransform : ResponseTransform
{
    private readonly AuthorizationTransportOptions _options;

    public AuthorizationTransportResponseTransform(AuthorizationTransportOptions options)
    {
        _options = options;
    }

    public override async ValueTask ApplyAsync(ResponseTransformContext context)
    {
        if (context.ProxyResponse is { } proxyResponse
            && HttpStatusCode.Unauthorized == proxyResponse.StatusCode)
        {
            string? scheme=null;
            if (_options.ChallengeSchemeSelector is { } schemeSelector) {
                scheme = schemeSelector(context);
            }
            scheme ??= _options.Scheme;
            await context.HttpContext.ChallengeAsync(scheme);
        }
    }
}
