using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;

using Yarp.ReverseProxy.Authentication;

namespace ReverseProxy.Tunnel.Backend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();

        builder.Services.AddAuthentication(
            configureOptions: (options) =>
            {
                options.DefaultScheme = "Default";
                options.DefaultChallengeScheme = "Default";
            }
            )
            .AddNegotiate()
            .AddTransportJwtBearerToken(
                configuration: builder.Configuration.GetSection("ReverseProxy:TransportJwtBearerToken"),
                configure: (options) => { })
            .AddPolicyScheme(
                authenticationScheme: "Default",
                displayName: "Default",
                configureOptions: static (options) =>
                {
                    options.ForwardDefaultSelector = TransportTunnelExtensions.CreateForwardDefaultSelector(
                        defaultTunnelAuthenticationScheme: TransportJwtBearerTokenDefaults.AuthenticationScheme,
                        defaultAuthenticationScheme: NegotiateDefaults.AuthenticationScheme);
                })
            ;

        builder.Services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            //.SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy("AuthenticatedUser", new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            ;

        builder.Services.AddControllers()
            .AddJsonOptions(
                static (options) => options.JsonSerializerOptions.WriteIndented = true);
        builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(
            static (options) => options.SerializerOptions.WriteIndented = true);

        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddAuthorizationTransportTransformProvider(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthorizationTransport"))
            .AddTransportTunnel(
                configureTunnelHttp2: (options) =>
                {
                    options.MaxConnectionCount = 1;
                    options.IsEnabled = true;
                })
            .AddTransportTunnelNegotiate()
            ;

        var app = builder.Build();

        // Using app.UseHttpsRedirection(); stops the tunnel to work.
        // The request comes from the normal HTTPS - endpoint AND from the TunnelTransport HTTP - endpoint.
        //app.UseWhen(
        //    static (context) => !context.IsTransportTunnelRequest(),
        //    static (app) => app.UseHttpsRedirection()
        //    );
        app.Use((context, next) => {
            if (context.GetEndpoint() is { } endpoint) {
                var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
                foreach (var metadata in endpoint.Metadata)
                {
                    logger.LogDebug("metadata: {metadata}", metadata.GetType().FullName);
                }
                }
            return next(context);
        });

        app.UseAuthentication();
        app.UseAuthorization();

        app.Map("/Backend",
            async (context) => {
                context.Response.Headers.ContentType = "text/plain";
                await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
            }).AllowAnonymous();

        app.Map("/WhereAmI",
            async (context) => {
                context.Response.Headers.ContentType = "text/plain";
                await context.Response.WriteAsync($"WhereAmI: Backend: {System.DateTime.Now:s}");
            }).AllowAnonymous();

        app.Map("/BackendDump",
            async (HttpContext context) =>
            {
                var result = await HttpRequestDump.GetDumpAsync(context, context.Request, false);
                return TypedResults.Ok(result);
            }).RequireAuthorization("AuthenticatedUser");

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
