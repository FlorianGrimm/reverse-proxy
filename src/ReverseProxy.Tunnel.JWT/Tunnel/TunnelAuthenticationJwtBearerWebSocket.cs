using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationJwtBearerWebSocket
    : ITunnelAuthenticationService
{
    private readonly TunnelAuthenticationJwtBearerOptions _options;
    private readonly ILogger _logger;

    public TunnelAuthenticationJwtBearerWebSocket(
        IOptions<TunnelAuthenticationJwtBearerOptions> options,
        ILogger<TunnelAuthenticationJwtBearerWebSocket> logger
        )
    {
        _options = options.Value;
        _logger = logger;
    }

    public string GetAuthenticationMode() => "JwtBearer";

    public string GetTransport() => "TunnelWebSocket";

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
    }

    public ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (context.User.Identity is ClaimsIdentity { IsAuthenticated: true } identity)
        {
            var appid = identity.Claims.FirstOrDefault(c => c.Type == "appid")?.Value;
            var appidacr = identity.Claims.FirstOrDefault(c => c.Type == "appidacr")?.Value;
            if (appid == _options.ClientId && appidacr == "1")
            {
                return ValueTask.FromResult<IResult?>(Results.StatusCode(401));
            }
        }
        return ValueTask.FromResult<IResult?>(default);
    }
}
