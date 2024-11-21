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

        // Using
        // app.UseHttpsRedirection();
        // stops the tunnel to work.
        // The request comes from the normal https - endpoint
        // AND from the TunnelTransport - endpoint.
        app.UseWhen(
            static (context) => !context.TryGetTransportTunnelByUrl(out var _),
            static (app) => app.UseHttpsRedirection()
            );

        //app.UseAuthorization();
        //app.UseAuthentication();

        app.Map("/Backend", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
        });

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
