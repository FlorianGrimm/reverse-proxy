using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Authentication;
internal class TunnelCertificateHandler
    : AuthenticationHandler<TunnelCertificateOptions>
{
#if NET8_0_OR_GREATER
    public TunnelCertificateHandler(IOptionsMonitor<TunnelCertificateOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

#else
    public TunnelCertificateHandler(IOptionsMonitor<TunnelCertificateOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }
#endif

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        return Task.FromResult(AuthenticateResult.NoResult());
    }
}
