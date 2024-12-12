using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Authentication;

internal class TunnelNegotiateHandler
    : TunnelAuthenticationHandler<TunnelNegotiateOptions>
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

    /*
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Context.GetEndpoint() is { } endpoint)
        {
            if (endpoint.Metadata.GetMetadata<TunnelAuthenticationMetadata>()?.TunnelAuthentication is { } tunnelAuthentication
                && endpoint.Metadata.GetMetadata<RouteModel>() is { } routeModel
                && routeModel.Cluster is { } cluster)
            {
                var (authenticateResult,f)= await tunnelAuthentication.HandleAuthenticateAsync(
                    Context,
                    cluster.Model.Config,
                    Scheme.Name,
                    ClaimsIssuer);
                if (authenticateResult is { }) { return authenticateResult; }
            }
        }
        return AuthenticateResult.NoResult();
    }
    */
}
