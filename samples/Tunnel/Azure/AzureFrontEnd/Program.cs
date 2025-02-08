
namespace AzureFrontEnd;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
        builder.Logging.AddLocalFile(configuration: builder.Configuration.GetSection("Logging:LocalFile"));


        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTransportTunnel()
            .AddTunnelServicesBasic(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic"))
            ;

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.Run();
    }
}
