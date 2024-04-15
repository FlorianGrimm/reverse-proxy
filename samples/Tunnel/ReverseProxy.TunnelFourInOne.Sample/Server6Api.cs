using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SampleTunnelFourInOne;

public class Server6Api : ServerBase
{
    private static WebApplication Create()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddJsonFile("appsettings.server6Api.json");

        builder.Services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.WriteIndented = true;
            });

        // TODO: later
        /*
        builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            ;
        builder.WebHost.UseReverseProxyTunnelBackEnd();
        */
        var app = builder.Build();

        app.UseWebSockets();
        app.MapControllers();

        return app;
    }

    public Server6Api()
        : base(Create())
    {
    }
}
