using Microsoft.AspNetCore.Builder;
namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.AddConsole();

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport()
            .AddTunnelTransportAnonymous()
            ;

        var app = builder.Build();

        // app.UseHttpsRedirection();
        app.UseWhen(
            static (context) => !context.TryGetTransportTunnelByUrl(out var _),
            static (app) => app.UseHttpsRedirection()
            );

        app.Map("/Backend", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
        });

        app.UseAuthorization();

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
