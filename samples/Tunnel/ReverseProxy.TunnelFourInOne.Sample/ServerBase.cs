using System.Runtime.CompilerServices;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SampleTunnelFourInOne;

public class ServerBase
{
    protected static WebApplication CreateCommon(string appsettingsJsonFile)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddJsonFile(appsettingsJsonFile);

        builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

        builder.Services.AddReverseProxyTunnel()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .UseReverseProxyTunnelBackendToFrontend(builder.WebHost);

        var app = builder.Build();
        app.MapReverseProxyTunnelFrontendToBackend();
        app.MapReverseProxy();

        return app;
    }

    protected WebApplication _app;

    public IHostApplicationLifetime Lifetime => _app.Services.GetRequiredService<IHostApplicationLifetime>();

    public ServerBase(WebApplication app)
    {
        _app = app;
    }

    public async Task RunAsync()
    {
        await _app.RunAsync();
    }
}
