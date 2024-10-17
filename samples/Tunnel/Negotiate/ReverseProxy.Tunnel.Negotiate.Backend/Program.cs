using Microsoft.AspNetCore.Authentication.Negotiate;

namespace ReverseProxy.Tunnel.Backend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
           .AddNegotiate();

        builder.Services.AddAuthorization(options =>
        {
            options.FallbackPolicy = options.DefaultPolicy;
        });


        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport(
                configureTunnelHttp2: options => { options.MaxConnectionCount = 1; },
                configureTunnelWebSocket: options => { options.MaxConnectionCount = 1; }
            ) /* for the servers that starts the tunnel transport connections */
            .AddTunnelTransportNegotiate()
#warning Needed
            //.ConfigureCertificateLoaderOptions(options =>
            //{
            //    options.CertificateRoot = System.AppContext.BaseDirectory;
            //})
            ;

        var app = builder.Build();

        // app.UseHttpsRedirection() will redirect if the request is a tunnel request;
        // which means that the browser is redirected to https://{tunnelId}/... which is not what we want.
        _ = app.UseWhen(
            static context => !context.TryGetTransportTunnelByUrl(out _),
            app => app.UseHttpsRedirection()
        );

        app.UseAuthorization();

        app.MapReverseProxy();

        app.Run();
    }
}
