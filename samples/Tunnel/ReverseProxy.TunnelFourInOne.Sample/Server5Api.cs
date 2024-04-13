using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SampleTunnelFourInOne;

public class Server5Api : ServerBase
{
    private static WebApplication Create()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddJsonFile("appsettings.server5Api.json");

        builder.Services.AddControllers()
            .AddJsonOptions(options =>
            {
                options.JsonSerializerOptions.WriteIndented = true;
            });

        var app = builder.Build();

        app.UseWebSockets();
        app.MapControllers();

        return app;
    }

    public Server5Api()
        : base(Create())
    {
    }
}
