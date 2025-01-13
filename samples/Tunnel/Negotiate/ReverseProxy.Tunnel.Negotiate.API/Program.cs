using Microsoft.AspNetCore.Authorization;

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
            }
            )
            .AddTransportJwtBearerToken(
                configuration: builder.Configuration.GetSection("ReverseProxy:TransportJwtBearerToken"),
                configure: (options) => { })
            .AddNegotiate()
            .AddPolicyScheme(
                authenticationScheme: "Default",
                displayName: "Default",
                configureOptions: static (options) =>
            {
                options.ForwardDefaultSelector =
                    static (context) => context.IsXForwardedHostRequest()
                        ? Yarp.ReverseProxy.Authentication.TransportJwtBearerTokenDefaults.AuthenticationScheme
                        : Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
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

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

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
