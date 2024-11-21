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
            .AddTunnelServices()
            .AddTunnelServicesAnonymous()
            ;

        var app = builder.Build();

        app.UseHttpsRedirection();
        //app.UseAuthorization();
        //app.UseAuthentication();
        app.Map("/Frontend", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Frontend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Frontend: {System.DateTime.Now:s}");
        });

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
