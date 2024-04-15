using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SampleTunnelFourInOne;

public class Server1FE : ServerBase
{
    private static WebApplication Create()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddJsonFile("appsettings.server1FE.json");

        builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

        builder.Services.AddReverseProxyTunnel()
            .UseReverseProxyTunnelBackendToFrontend(builder.WebHost);

        var app = builder.Build();

        app.MapReverseProxyTunnelFrontendToBackend();
        app.MapReverseProxy();

        return app;
    }

    public Server1FE()
        : base(Create())
    {
    }
}
