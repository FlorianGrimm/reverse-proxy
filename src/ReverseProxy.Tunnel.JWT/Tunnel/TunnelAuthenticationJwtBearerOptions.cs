using System;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelAuthenticationJwtBearerOptions {
    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public string? Audience { get; set; }

    public void Bind(IConfiguration configuration)
    {
        TenantId = configuration[nameof(TenantId)];
        ClientId = configuration[nameof(ClientId)];
        Audience = configuration[nameof(Audience)];
    }

    public void ConfigureBearerToken(
        JwtBearerOptions jwtBearerOptions)
    {
        jwtBearerOptions.Audience = Audience;
        jwtBearerOptions.Authority = $"https://login.microsoftonline.com/{TenantId}/v2.0";
        jwtBearerOptions.TokenValidationParameters.ValidAudiences = [
            $"api://{ClientId}",
            ClientId
            ];
        jwtBearerOptions.TokenValidationParameters.ValidIssuers = [
            $"https://login.microsoftonline.com/{TenantId}/v2.0",
            $"https://sts.windows.net/{TenantId}/v2.0",
            $"https://sts.windows.net/{TenantId}/"
            ];
    }

    public static Action<JwtBearerOptions> ConfigureJwtBearerOptions(IConfiguration configuration) {
        return options =>
        {
            var tunnelOptions = new TunnelAuthenticationJwtBearerOptions();
            tunnelOptions.Bind(configuration);
            tunnelOptions.ConfigureBearerToken(options);
        };
    }
}
