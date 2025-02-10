namespace Yarp.ReverseProxy.TunnelBackEnd;

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
            .AddTransportTunnelBasic(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic"))
            ;

        var app = builder.Build();

        app.MapReverseProxy();
        app.Run();
    }
}
