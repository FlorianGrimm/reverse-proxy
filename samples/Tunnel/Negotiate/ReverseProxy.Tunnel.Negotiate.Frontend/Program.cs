using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Tunnel;

namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddSingleton<IForwarderHttpClientFactory, NegotiateForwarderHttpClientFactory>();

        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();

        builder.Services.AddAuthentication(
            //
            "switch"
            )
            .AddNegotiate()
            .AddTunnelServicesNegotiate()
            .AddPolicyScheme(
                authenticationScheme: "switch",
                displayName: "switch",
                configureOptions: static (options) =>
                {
#if true
                    options.ForwardDefaultSelector = static (context) =>
                    {
                        if (context.GetEndpoint().TryGetTunnelAuthenticationScheme(out var authenticationScheme))
                        {
                            return authenticationScheme;
                        }
                        else
                        {
                            return Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                        }
                    };
#else
                    options.ForwardDefaultSelector = static (context) =>
                        context.GetEndpoint().GetTunnelAuthenticationSchemeOrDefault(
                            Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme);
#endif
                });

        builder.Services.AddAuthorization((options) =>
        {
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
                .AddAuthorizationTransportTransformProvider(
                    configuration: builder.Configuration.GetSection("ReverseProxy:AuthorizationTransport"))
                ;

        var app = builder.Build();

        app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();
        app.Map("/Frontend", async (context) =>
        {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Frontend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) =>
        {
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
                UserIsAuthenticated = context.User.Identity?.IsAuthenticated,
                UserName = context.User.Identity?.Name,
                UserClaims = context.User.Claims.Select(claim => new { Type = claim.Type, Value = claim.Value }),
                Body = await new StreamReader(request.Body).ReadToEndAsync(),
            };
            return TypedResults.Ok(result);
        });

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}


internal sealed class NegotiateForwarderHttpClientFactory : ForwarderHttpClientFactory
{
    protected override HttpMessageHandler WrapHandler(ForwarderHttpClientContext context, HttpMessageHandler handler)
    {
        if (handler is SocketsHttpHandler socketsHttpHandler)
        {
            socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
        }
        return handler;
    }
}
