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
#endif

using Yarp.ReverseProxy.Tunnel;

namespace ReverseProxy.Tunnel.Frontend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        builder.Services.AddAuthentication()
            .AddJwtBearer(jwtBearerOptions => {
                var options = new TunnelAuthenticationJwtBearerOptions();
                builder.Configuration.GetRequiredSection("AzureAd").Bind(options);
                TunnelAuthenticationJwtBearer.ConfigureBearerToken(
                    jwtBearerOptions, options);
            })
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
