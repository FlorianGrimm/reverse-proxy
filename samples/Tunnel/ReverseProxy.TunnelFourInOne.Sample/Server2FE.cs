using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SampleTunnelFourInOne;

public class Server2FE : ServerBase
{
    private static WebApplication Create()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddJsonFile("appsettings.server2FE.json");

        builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .UseReverseProxyTunnelBackendToFrontend(builder.WebHost)
            ;
        
        var app = builder.Build();

        app.MapReverseProxyTunnelFrontendToBackend();
        app.MapReverseProxy();

        return app;
    }

    public Server2FE()
        : base(Create())
    {
    }
}
