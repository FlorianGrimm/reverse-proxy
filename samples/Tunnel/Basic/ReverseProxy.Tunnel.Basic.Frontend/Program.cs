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

/*
TODO: Problem with authorization

https://localhost:5001/FrontendDump
https://localhost:5001/FrontendDumpUser
https://localhost:5001/LoopbackUser/FrontendDump?x=4
https://localhost:5001/LoopbackAnonymous/FrontendDump?x=4
https://localhost:5001/LoopbackUser/API
https://localhost:5001/LoopbackAnonymous/API
https://localhost:5001/LoopbackUser/APIDump
https://localhost:5001/LoopbackAnonymous/APIDump
https://localhost:5001/
https://localhost:5001/
https://localhost:5001/
https://localhost:5001/

https://localhost:5003/
https://localhost:5005/

 */
public class Program
{
    private static ILogger logger = null!;

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
            .AddNegotiate((options) => { })
            .AddTunnelAuthentication()
            .AddPolicyScheme(
                authenticationScheme: "Default",
                displayName: "Default",
                configureOptions: static (options) =>
                {
                    options.ForwardDefaultSelector = (HttpContext httpContext) =>
                    {
                        try
                        {
                            var hasTunnelAuthenticationScheme = TunnelAuthenticationSchemeExtensions.TryGetTunnelAuthenticationScheme(httpContext.GetEndpoint(), out var result);
                            if (!hasTunnelAuthenticationScheme)
                            {
                                result = NegotiateDefaults.AuthenticationScheme;
                            }
                            logger.LogDebug("ForwardDefaultSelector:(hasTunnelAuthenticationScheme:{hasTunnelAuthenticationScheme};) -> result:{ForwardDefaultSelector};", hasTunnelAuthenticationScheme, result);
                            return result;
                        }
                        catch (System.Exception error)
                        {
                            logger.LogError(error, "ForwardDefaultSelector");
                            return null;
                        }
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
        logger = app.Services.GetRequiredService<ILogger<Program>>();

        //app.UseHttpsRedirection();
        app.UseAuthentication();
        app.UseAuthorization();

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
                logger.LogInformation("FrontendDump: {result}", result);
                return TypedResults.Ok(result);
            }).AllowAnonymous();

        app.Map("/FrontendDumpUser",
            async (HttpContext context) =>
            {
                var result = await HttpRequestDump.GetDumpAsync(context, context.Request, false);
                logger.LogInformation("FrontendDumpUser: {result}", result);
                return TypedResults.Ok(result);
            }).RequireAuthorization("AuthenticatedUser");

        app.Map("/LoopbackAnonymous/{forward}",
            async (HttpContext context, string forward) =>
            {
                var request = context.Request;
                var httpRequestDump = await HttpRequestDump.GetDumpAsync(context, context.Request, false);
                try
                {
                    while (forward is { Length: > 0 })
                    {
                        if (forward.StartsWith("LoopbackAnonymous"))
                        {
                            forward = forward.Substring("LoopbackAnonymous".Length).TrimStart('/');
                            continue;
                        }
                        if (forward.StartsWith("LoopbackUser"))
                        {
                            forward = forward.Substring("LoopbackUser".Length).TrimStart('/');
                            continue;
                        }
                        break;
                    }
                    var jwtUtilityService = context.RequestServices.GetRequiredService<AuthorizationTransportJWTUtilityService>();
                    using var client = context.RequestServices.GetRequiredService<ILoopbackForwardHttpClientFactory>().CreateHttpClient();
                    var requestMessage = new HttpRequestMessage(HttpMethod.Get, "/" + forward);
                    jwtUtilityService.SetAuthorizationHeaderWithUserAasJwtToken(context.User, requestMessage);

                    using var response = await client.SendAsync(requestMessage, context.RequestAborted);

                    var content = await response.Content.ReadAsStringAsync();
                    if (string.IsNullOrEmpty(content))
                    {
                        content = "empty";
                    }
                    var transportMode = context.Features.Get<IConnectionTransportTunnelFeature>()?.TransportMode;
                    return Results.Ok(new {
                        StatusCode = response.StatusCode,
                        Headers = response.Headers.ToString().Split(Environment.NewLine),
                        TransportMode= transportMode,
                        Content = content,
                        HttpRequest = httpRequestDump,
                    });
                }
                catch (Exception ex)
                {
                    return Results.BadRequest(ex.Message);
                }
            }).AllowAnonymous();

        app.Map("/LoopbackUser/{forward}",
            async (HttpContext context, string forward) =>
            {
                var request = context.Request;
                var httpRequestDump = await HttpRequestDump.GetDumpAsync(context, context.Request, false);
                try
                {
                    while (forward is { Length: > 0 })
                    {
                        if (forward.StartsWith("LoopbackAnonymous"))
                        {
                            forward = forward.Substring("LoopbackAnonymous".Length).TrimStart('/');
                            continue;
                        }
                        if (forward.StartsWith("LoopbackUser"))
                        {
                            forward = forward.Substring("LoopbackUser".Length).TrimStart('/');
                            continue;
                        }
                        break;
                    }
                    var jwtUtilityService = context.RequestServices.GetRequiredService<AuthorizationTransportJWTUtilityService>();
                    using var client = context.RequestServices.GetRequiredService<ILoopbackForwardHttpClientFactory>().CreateHttpClient();
                    var requestMessage = new HttpRequestMessage(HttpMethod.Get, "/" + forward);
                    jwtUtilityService.SetAuthorizationHeaderWithUserAasJwtToken(context.User, requestMessage);

                    using var response = await client.SendAsync(requestMessage, context.RequestAborted);

                    var content = await response.Content.ReadAsStringAsync();
                    if (string.IsNullOrEmpty(content))
                    {
                        content = "empty";
                    }
                    return Results.Ok(new {
                        StatusCode = response.StatusCode,
                        Headers = response.Headers.ToString().Split(Environment.NewLine),
                        Content = content,
                        HttpRequest = httpRequestDump,
                    });
                }
                catch (Exception ex)
                {
                    return Results.BadRequest(ex.Message);
                }
            }).RequireAuthorization("AuthenticatedUser");

        app.MapControllers();
        app.MapReverseProxy();
        app.Run();
    }
}
