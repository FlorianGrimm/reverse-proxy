using System;

using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Tunnel;

namespace ReverseProxy.Tunnel.Frontend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        //var socketPath = System.IO.Path.GetTempFileName();
        //var socketPathDS = socketPath.Replace(@"\", @"\\");
        //builder.Configuration.AddInMemoryCollection(new System.Collections.Generic.Dictionary<string, string?>
        //{
        //    { "Kestrel:Endpoints:Loopback:Url", $"https://unix:{socketPathDS}" }
        //});
        
        

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
                    ILogger? logger = null;
                    options.ForwardDefaultSelector = (HttpContext httpContext) =>
                    {
                        logger ??= httpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                        var hasTunnelAuthenticationScheme = TunnelAuthenticationSchemeExtensions.TryGetTunnelAuthenticationScheme(httpContext.GetEndpoint(), out var result);
                        if (!hasTunnelAuthenticationScheme)
                        {
                            result = NegotiateDefaults.AuthenticationScheme;
                        }
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
            .AddTransportTunnel()
            .AddTransportLoopback(
                configure: (options) =>
                {
                    //options.SocketPath = socketPath;
                }
            )
            .AddTunnelServices()
            .AddTunnelServicesBasic(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic"))
            .AddAuthorizationTransportTransformProvider(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthorizationTransport"),
                configure: (options) =>
                {
                    options.ChallengeSchemeSelector = static (ResponseTransformContext responseTransformContext) =>
                    {
                        //string? result=null; return result;
                        return NegotiateDefaults.AuthenticationScheme;
                    };
                })
            ;

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

        app.Map("/Todo",
            async (HttpContext context) =>
            {
                try
                {
                    var jwtUtilityService = context.RequestServices.GetRequiredService<AuthorizationTransportJWTUtilityService>();
                    using var client = context.RequestServices.GetRequiredService<ILoopbackForwardHttpClientFactory>().CreateHttpClient();
                    var requestMessage = new HttpRequestMessage(
                        HttpMethod.Get,
                        "/API"
                        );
                    if (jwtUtilityService.CreateJWTClaimsIdentity(context.User) is { } jwtClaimsIdentity)
                    {
                        var jwtToken = jwtUtilityService.CreateJWTToken(jwtClaimsIdentity);
                        requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);
                    }
                    using var response = await client.SendAsync(requestMessage, context.RequestAborted);
                    var content = await response.Content.ReadAsStringAsync();
                    return Results.Ok(content);
                }
                catch (Exception ex)
                {
                    return Results.BadRequest(ex.Message);
                }
            }).AllowAnonymous();
        //.RequireAuthorization("AuthenticatedUser");

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
