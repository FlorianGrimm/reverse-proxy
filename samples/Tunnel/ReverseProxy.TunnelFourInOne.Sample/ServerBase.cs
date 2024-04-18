using System.Runtime.CompilerServices;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
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
        app.MapReverseProxyTunnelFrontendToBackend()
            .MapReverseProxy();

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
        var listeners = _app.Services.GetServices<IConnectionListenerFactory>();
        var urls = _app.Configuration.GetValue<string>("Urls");
        System.Console.Out.WriteLine($"Server {GetType().Name} running at: {urls}");
        await _app.RunAsync();
    }
}
