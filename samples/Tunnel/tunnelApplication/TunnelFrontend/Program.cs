
namespace Yarp.ReverseProxy.TunnelFrontEnd;

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
            .AddTunnelServices()
            .AddTunnelServicesBasic(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic"))
            ;
        var app = builder.Build();

        app.Run();
    }
}
