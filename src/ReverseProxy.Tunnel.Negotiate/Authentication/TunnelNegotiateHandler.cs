using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Authentication;

internal class TunnelNegotiateHandler
    : AuthenticationHandler<TunnelNegotiateOptions>
{
#if NET8_0_OR_GREATER
    public TunnelNegotiateHandler(
        IOptionsMonitor<TunnelNegotiateOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder
        )
        : base(options: options, logger: logger, encoder: encoder)
    {
    }
#else
    public TunnelNegotiateHandler(
        IOptionsMonitor<TunnelNegotiateOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock
        )
        : base(options, logger, encoder, clock)
    {
    }
#endif

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Context.GetEndpoint()?.Metadata.GetMetadata<TunnelAuthenticationFeature>()?.TunnelAuthentication is { } tunnelAuthentication) {
            return await tunnelAuthentication.HandleAuthenticateAsync(Context, Scheme.Name, ClaimsIssuer);
        }

        ////Context.Request.Cookies.TryGetValue
        ////var tunnelAuthenticationCookieService = Context.RequestServices.GetService<ITunnelAuthenticationCookieService>();
        //var tunnelAuthenticationConfigService = Context.RequestServices.GetService<ITunnelAuthenticationConfigService>();
        //if (tunnelAuthenticationConfigService is null) {
        //    // return Task.FromResult(AuthenticateResult.NoResult());
        //    return AuthenticateResult.NoResult();
        //}
        //if (tunnelAuthenticationConfigService.TryGetTunnelAuthenticationServices(
        //    TunnelConstants.TransportNameTunnelHTTP2,
        //    TunnelNegotiateConstants.NegotiateAuthenticationName,
        //    out var tunnelAuthenticationService)
        //    && tunnelAuthenticationService is ITunnelAuthenticationServiceV2 tunnelAuthenticationServiceV2
        //    ) {
        //    return await tunnelAuthenticationServiceV2.HandleAuthenticateAsync(Context);

        //    //tunnelAuthenticationCookieService.ValidateCookie

        //    //        private readonly LazyProxyConfigManager _proxyConfigManagerLazy;
        //    //private readonly ITunnelAuthenticationCookieService _cookieService;
        //    // this.Context.Request.RouteValues["clusterId"]
        //    //var identity = new ClaimsIdentity([new Claim(ClaimsIdentity.DefaultNameClaimType, "Tunnel", ClaimsIssuer)], Scheme.Name);
        //    //var principal = new ClaimsPrincipal(identity);
        //    //var ticket = new AuthenticationTicket(principal, Scheme.Name);
        //    //return Task.FromResult(AuthenticateResult.Success(ticket));
        //}

        ////return Task.FromResult(AuthenticateResult.NoResult());

        return AuthenticateResult.NoResult();
    }
}
