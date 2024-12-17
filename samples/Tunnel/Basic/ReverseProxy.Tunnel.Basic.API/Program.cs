using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();

        // https://learn.microsoft.com/en-us/aspnet/core/security/authorization/limitingidentitybyscheme?view=aspnetcore-9.0
        builder.Services.AddAuthentication(
            configureOptions: (options) =>
            {
                options.DefaultScheme = "Default";
                options.DefaultChallengeScheme = "Default";
            })
            .AddNegotiate()
            .AddTransportJwtBearerToken(
                configuration: builder.Configuration.GetSection("ReverseProxy:TransportJwtBearerToken"),
                configure: (options) => { })
            .AddPolicyScheme(
                authenticationScheme: "Default",
                displayName: "Default",
                configureOptions: static (options) =>
                {
                    ILogger? logger = null;
                    options.ForwardDefaultSelector = (context) =>
                        {
                            logger ??= context.RequestServices.GetRequiredService<ILogger<Program>>();
                            var isForwardedRequest = context.IsForwardedRequest();
                            var result = isForwardedRequest
                                ? Yarp.ReverseProxy.Authentication.TransportJwtBearerTokenDefaults.AuthenticationScheme
                                : Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                            logger.LogDebug("ForwardDefaultSelector:(isForwardedRequest:{isForwardedRequest};) -> result:{ForwardDefaultSelector};", isForwardedRequest, result);
                            return result;
                        };
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

        builder.Services.AddHealthChecks();
        // TODO:AddHealthChecks
        /*
        builder.Services.AddHealthChecks()
            .AddCheck<SampleHealthCheck>(
                "Sample",
                failureStatus: HealthStatus.Degraded,
                tags: new[] { "sample" });
        */

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapHealthChecks(
            pattern: "/health",
            options: new HealthCheckOptions { })
            .AllowAnonymous();

        app.Map("/API",
            async (HttpContext context) =>
            {
                context.Response.Headers.ContentType = "text/plain";
                await context.Response.WriteAsync($"API: {System.DateTime.Now:s}");
            }).AllowAnonymous();

        app.Map("/WhereAmI",
            async (HttpContext context) =>
            {
                context.Response.Headers.ContentType = "text/plain";
                await context.Response.WriteAsync($"WhereAmI: API: {System.DateTime.Now:s}");
            }).AllowAnonymous();

        app.Map("/APIDump",
            async (HttpContext context) =>
            {
                var result = await HttpRequestDump.GetDumpAsync(context, context.Request, false);
                return TypedResults.Ok(result);
            }).RequireAuthorization("AuthenticatedUser");

        app.MapControllers();

        app.Run();
    }
}
