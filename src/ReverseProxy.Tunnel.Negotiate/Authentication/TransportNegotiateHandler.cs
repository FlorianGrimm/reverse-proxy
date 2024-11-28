using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Authentication;

internal class TransportNegotiateHandler
    : AuthenticationHandler<TransportNegotiateOptions>
{
#if NET8_0_OR_GREATER
    public TransportNegotiateHandler(
        IOptionsMonitor<TransportNegotiateOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder
        )
        : base(options: options, logger: logger, encoder: encoder)
    {
        _logger = logger.CreateLogger<TransportNegotiateHandler>();
    }
#else
    public TransportNegotiateHandler(
        IOptionsMonitor<TransportNegotiateOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock
        )
        : base(options, logger, encoder, clock)
    {
        _logger = logger.CreateLogger<TransportNegotiateHandler>();
    }
#endif

    private readonly ILogger _logger;

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new ClaimsIdentity([new Claim(ClaimsIdentity.DefaultNameClaimType, "Tunnel", ClaimsIssuer)], Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
