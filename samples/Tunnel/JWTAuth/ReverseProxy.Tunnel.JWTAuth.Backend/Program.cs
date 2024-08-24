namespace ReverseProxy.Tunnel.Backend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport(
                configureTunnelHttp2: options => { options.MaxConnectionCount = 1; },
                configureTunnelWebSocket: options => { options.MaxConnectionCount = 1; }
            ) /* for the servers that starts the tunnel transport connections */
            .AddTunnelTransportJwtBearer()
            ;

        var app = builder.Build();

        // app.UseHttpsRedirection() will redirect if the request is a tunnel request;
        // which means that the borwser is redirected to https://{tunnelId}/... which is not what we want.
        app.UseWhen(
            static context => !context.TryGetTransportTunnelByUrl(out var _),
            app => app.UseHttpsRedirection()
        );

        app.UseAuthorization();

        app.MapReverseProxy();

        app.Run();
    }
}
