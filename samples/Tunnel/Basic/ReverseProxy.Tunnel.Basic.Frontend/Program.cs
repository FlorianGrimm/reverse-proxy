using System;

using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Tunnel;

namespace ReverseProxy.Tunnel.Frontend;

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
            })
            .AddNegotiate()
            .AddTunnelAuthentication()
            .AddPolicyScheme(
                authenticationScheme: "Default",
                displayName: "Default",
                configureOptions: static (options) =>
                {
                    // options.ForwardDefaultSelector = TunnelAuthenticationSchemeExtensions
                    //     .CreateForwardDefaultSelector(NegotiateDefaults.AuthenticationScheme);
                    ILogger? logger = null;
                    options.ForwardDefaultSelector = (HttpContext httpContext) =>
                    {
                        logger ??= httpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                        var hasTunnelAuthenticationScheme = TunnelAuthenticationSchemeExtensions.TryGetTunnelAuthenticationScheme(httpContext.GetEndpoint(), out var result);
                        logger.LogDebug("ForwardDefaultSelector:(hasTunnelAuthenticationScheme:{hasTunnelAuthenticationScheme};) -> result:{ForwardDefaultSelector};", hasTunnelAuthenticationScheme, result);
                        return result;
                    };
                });

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
            .AddTunnelServices()
            .AddTunnelServicesBasic(
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

        app.UseHttpsRedirection();
        app.UseAuthorization();
        app.UseAuthentication();

        app.MapHealthChecks(
            pattern: "/health",
            options: new HealthCheckOptions { })
            .AllowAnonymous();

        app.Map("/Frontend",
            async (context) =>
            {
                context.Response.Headers.ContentType = "text/plain";
                await context.Response.WriteAsync($"Frontend: {System.DateTime.Now:s}");
            }).AllowAnonymous();

        app.Map("/WhereAmI",
            async (context) =>
            {
                context.Response.Headers.ContentType = "text/plain";
                await context.Response.WriteAsync($"WhereAmI: Frontend: {System.DateTime.Now:s}");
            }).AllowAnonymous();

        app.Map("/FrontendDump",
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
