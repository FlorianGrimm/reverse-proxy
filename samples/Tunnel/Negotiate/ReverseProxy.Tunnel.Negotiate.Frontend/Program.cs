using Microsoft.AspNetCore.Authorization;

using Yarp.ReverseProxy.Forwarder;

namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
#warning TODO: Handle user
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddSingleton<IForwarderHttpClientFactory, NegotiateForwarderHttpClientFactory>();

        builder.Logging.AddConsole();

        builder.Services.AddAuthentication(
            Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme
            ).AddNegotiate();

        builder.Services.AddAuthorization((options) => {
            //options.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
            //options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelServices()
            .AddTunnelServicesNegotiate()
            ;

        var app = builder.Build();

        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        app.Map("/Frontend", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Frontend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"WhereAmI: Frontend: {System.DateTime.Now:s}");
        });
        app.Map("/FrontendDump", async (HttpContext context) =>
        {
            var request = context.Request;
            var result = new {
                request.Protocol,
                request.Method,
                request.Scheme,
                Host = request.Host.Value,
                PathBase = request.PathBase.Value,
                Path = request.Path.Value,
                Query = request.QueryString.Value,
                Headers = request.Headers.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToArray()),
                Time = DateTimeOffset.UtcNow,
                Body = await new StreamReader(request.Body).ReadToEndAsync(),
            };
            return TypedResults.Ok(result);
        });

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}


class NegotiateForwarderHttpClientFactory : ForwarderHttpClientFactory {
    protected override HttpMessageHandler WrapHandler(ForwarderHttpClientContext context, HttpMessageHandler handler)
    {
        if (handler is SocketsHttpHandler socketsHttpHandler) {
            socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
        }
        return handler;
    }
}
