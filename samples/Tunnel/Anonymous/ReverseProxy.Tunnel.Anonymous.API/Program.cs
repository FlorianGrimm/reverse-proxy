namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.AddConsole();

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        var app = builder.Build();

        app.UseHttpsRedirection();

        //app.UseAuthorization();
        //app.UseAuthentication();

        app.Map("/API", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"API: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"API: {System.DateTime.Now:s}");
        });

        app.MapControllers();

        app.Run();
    }
}
