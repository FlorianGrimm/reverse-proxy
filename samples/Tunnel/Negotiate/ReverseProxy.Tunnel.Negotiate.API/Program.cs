
namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}
