using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

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

        builder.Services.AddAuthorization((options) =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
            // options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });

        builder.Services.AddControllers()
            .AddJsonOptions(
                static (options) => options.JsonSerializerOptions.WriteIndented = true);
        builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(
            static (options) => options.SerializerOptions.WriteIndented = true);

        builder.Services.AddControllers()
            .AddJsonOptions(
                static (options) => options.JsonSerializerOptions.WriteIndented = true);
        builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(
            static (options) => options.SerializerOptions.WriteIndented = true);

        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTransportTunnel()
            .AddTransportTunnelBasic(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic"))
            .AddAuthorizationTransportTransformProvider(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthorizationTransport"));


        builder.Services.AddHealthChecks();
#warning TODO:AddHealthChecks
        /*
        builder.Services.AddHealthChecks()
            .AddCheck<SampleHealthCheck>(
                "Sample",
                failureStatus: HealthStatus.Degraded,
                tags: new[] { "sample" });
        */

        var app = builder.Build();

        // Using app.UseHttpsRedirection(); stops the tunnel to work.
        // The request comes from the normal HTTPS - endpoint AND from the TunnelTransport HTTP - endpoint.
        app.UseWhen(
            static (context) => !context.IsTransportTunnelRequest(),
            static (app) => {
                app.UseHttpsRedirection();
                app.UseAuthorization();
                app.UseAuthentication();
            });

        app.UseWhen(
            static (context) => context.IsTransportTunnelRequest(),
            static (app) => {
                app.UseAuthorization();
                app.UseAuthentication();
            });

        app.MapHealthChecks(
            pattern: "/health",
            options: new HealthCheckOptions
            {
                AllowCachingResponses = true
            }).AllowAnonymous();


        app.Map("/Backend", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) => {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"WhereAmI: Backend: {System.DateTime.Now:s}");
        });
        app.Map("/BackendDump", async (HttpContext context) =>
        {
            var result = await HttpRequestDump.GetDumpAsync(context, context.Request, false);
            return TypedResults.Ok(result);
        });

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
