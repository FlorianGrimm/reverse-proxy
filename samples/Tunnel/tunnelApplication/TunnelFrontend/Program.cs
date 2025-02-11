
namespace Yarp.ReverseProxy.TunnelFrontEnd;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
        builder.Logging.AddLocalFile(
            configure: (options) => {
                if (System.Environment.GetEnvironmentVariable("HOME") is { Length: > 0 } home)
                {
                    options.BaseDirectory = home;
                }
                else {
                    options.BaseDirectory = builder.Environment.ContentRootPath;
                }
                options.LogDirectory = "LogFiles\\Application";
                
            },
            configuration: builder.Configuration.GetSection("Logging:LocalFile"));

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
