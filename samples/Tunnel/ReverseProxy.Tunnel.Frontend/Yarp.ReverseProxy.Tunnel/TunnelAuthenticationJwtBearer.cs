using System.Security.Claims;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;
internal sealed class TunnelAuthenticationJwtBearer
    : ITunnelAuthenticationService
{
    private readonly TunnelAuthenticationJwtBearerOptions _options;
    private readonly ILogger _logger;

    public TunnelAuthenticationJwtBearer(
        IOptions<TunnelAuthenticationJwtBearerOptions> options,
        ILogger<TunnelAuthenticationJwtBearer> logger
        )
    {
        _options = options.Value;
        _logger = logger;
    }

    public string GetAuthenticationName() => "JwtBearer";

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (context.User.Identity is ClaimsIdentity { IsAuthenticated: true} identity) {
            var appid = identity.Claims.FirstOrDefault(c => c.Type == "appid")?.Value;
            var appidacr = identity.Claims.FirstOrDefault(c => c.Type == "appidacr")?.Value;
            if (appid == _options.ClientId && appidacr == "1")
            {
                return true;
            }
        }
        return false;
    }

    public static void ConfigureBearerToken(
        JwtBearerOptions jwtBearerOptions,
        TunnelAuthenticationJwtBearerOptions options)
    {
        var tenantId = options.TenantId;
        var clientId = options.ClientId;
        var audience = options.Audience;
        jwtBearerOptions.Audience = audience;
        jwtBearerOptions.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
        jwtBearerOptions.UseSecurityTokenValidators = false;
        jwtBearerOptions.TokenValidationParameters.ValidAudiences = [
            $"api://{clientId}",
            clientId
            ];
        jwtBearerOptions.TokenValidationParameters.ValidIssuers = [
            $"https://login.microsoftonline.com/{tenantId}/v2.0",
            $"https://sts.windows.net/{tenantId}/v2.0",
            $"https://sts.windows.net/{tenantId}/"
            ];
    }
}
