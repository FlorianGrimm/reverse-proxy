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

using System.Security.Claims;

using Microsoft.AspNetCore.Authentication.Negotiate;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Tunnel;

namespace ReverseProxy.Tunnel.Frontend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
           .AddNegotiate();

        builder.Services.AddAuthorization(options =>
        {
            // By default, all incoming requests will be authorized according to the default policy.
            //options.FallbackPolicy = options.DefaultPolicy;
        });

        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        builder.Services.AddReverseProxyCertificateManager();

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetRequiredSection("ReverseProxy"))
            .AddAuthorizationTransportTransformProvider(
                configure: (options) =>
                {
                    options.Issuer = "itsme";
                    options.Audience = "itsyou";
                    options.SigningCertificateConfig = new CertificateConfig
                    {
                        Subject = "CN=my jwt sign for localhost",
                        StoreName = "My",
                        StoreLocation = "CurrentUser",
                        AllowInvalid = true,
                    };
                })
            .AddTunnelServices()
            .AddTunnelServicesNegotiate()
            ;

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseRouting();
        app.Map("/frontend", async (context) =>
        {
            context.Response.ContentType = "text/plain";
            await context.Response.WriteAsync("Frontend\r\n");
            if (context.User.Identity is { } identity
                && identity.IsAuthenticated == true)
            {
                await context.Response.WriteAsync("Authenticated\r\n");
                if (identity is ClaimsIdentity claimsIdentity)
                {
                    foreach (var claim in claimsIdentity.Claims)
                    {
                        await context.Response.WriteAsync($"{claim.Type}: {claim.Value}\r\n");
                    }
                }

            }
            
        });
        app.MapReverseProxy();

        app.Run();
    }
}
