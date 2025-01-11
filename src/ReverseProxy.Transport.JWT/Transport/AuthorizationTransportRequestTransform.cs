using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;

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

            var proxyRequest = context.ProxyRequest;
            var httpContext = context.HttpContext;

            ClaimsPrincipal? inboundUser;
            {
                var contextUser = httpContext.User;

                if (contextUser.Identity is null
                    || !contextUser.Identity.IsAuthenticated)
                {
                    string? scheme = null;
                    if (_options.AuthenticationSchemeSelector is { } schemeSelector)
                    {
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
                var outboundClaimsIdentity = AuthorizationTransportJWTUtility.CreateJWTClaimsIdentity(inboundUser, _options);

                if (outboundClaimsIdentity.Claims.Any())
                {
                    var jwtToken = AuthorizationTransportJWTUtility.CreateJWTToken(outboundClaimsIdentity, signingCredentials, _options);

                    proxyRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);

                    //if (_options.RemoveHeaderAuthenticate)
                    //{
                    proxyRequest.Headers.Remove(WWWAuthenticate);
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



internal sealed class AuthorizationTransportResponseTransform(AuthorizationTransportOptions options) : ResponseTransform
{
    private readonly AuthorizationTransportOptions _options = options;

    public override async ValueTask ApplyAsync(ResponseTransformContext context)
    {
        // If the proxy response status code is Unauthorized (401),
        // initiate a challenge to authenticate the user using the specified scheme.
        if (context.ProxyResponse is { } proxyResponse
            && HttpStatusCode.Unauthorized == proxyResponse.StatusCode)
        {
            // this does not work since context.ProxyResponse is the one the is returned to the client
            // and context.HttpContext is not the original
            // big TODO future me
            string? scheme = null;
            if (_options.ChallengeSchemeSelector is { } schemeSelector)
            {
                scheme = schemeSelector(context);
            }
            scheme ??= _options.Scheme;
            await context.HttpContext.ChallengeAsync(scheme);

            // so instead of that, we might use 307 Temporary Redirect and redirect to a login page
            // someting like /login?challange=scheme&returnUrl=originalUrl
        }
    }
}
