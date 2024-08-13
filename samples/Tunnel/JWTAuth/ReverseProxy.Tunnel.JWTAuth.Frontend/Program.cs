#if README
Create a AppRegistration in Azure AD and update the configuration in appsettings.json or user secrets.
You need the Application ID URI. It should be in the format `api://{ClientId}`.
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "ClientId": "....",
    "TenantId": "....",
    "Audience": "api://{ClientId}",
    "ClientSecret": "...."
  }
}

--------------------------------
| Browser                      |
| https://localhost:5001/index |
--------------------------------
            |           ^
            |           |
            v           |
--------------------------------
| ReverseProxy.Tunnel.Frontend |
| https://localhost:5001/      |
--------------------------------
        |     ||     /\
        |     ||     ||
        ^     \/     ||
--------------------------------
| ReverseProxy.Tunnel.Backend  |
| https://localhost:5003/      |
--------------------------------
                 |  ^
                 |  |
                 v  |
--------------------------------
| ReverseProxy.Tunnel.API      |
| https://localhost:5005/      |
--------------------------------

#endif

using Yarp.ReverseProxy.Tunnel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace ReverseProxy.Tunnel.Frontend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        builder.Services.AddAuthentication()
            .AddJwtBearer(TunnelAuthenticationJwtBearerOptions.ConfigureJwtBearerOptions(builder.Configuration.GetRequiredSection("AzureAd")))
            ;
        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetRequiredSection("ReverseProxy"))
            .AddTunnelServices() // enable tunnel listener
            .AddTunnelAuthenticationJwtBearer(builder.Configuration.GetRequiredSection("AzureAd")) // add custom JWT bearer authentication
            ;

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapReverseProxy();

        app.Run();
    }
}
