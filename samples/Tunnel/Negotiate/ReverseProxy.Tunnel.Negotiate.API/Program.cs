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
                options.DefaultScheme = "switch";
                options.DefaultChallengeScheme = "switch";
            }
            )
            .AddTransportJwtBearerToken(
                configuration: builder.Configuration.GetSection("ReverseProxy:TransportJwtBearerToken"),
                configure: (options) => { })
            .AddNegotiate()
            .AddPolicyScheme(
                authenticationScheme: "switch",
                displayName: "switch",
                configureOptions: static (options) =>
            {
                options.ForwardDefaultSelector =
                    static (context) => context.IsTransportJwtBearerTokenAuthentication()
                        ? Yarp.ReverseProxy.Authentication.TransportJwtBearerTokenDefaults.AuthenticationScheme
                        : Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
            })
            ;

        builder.Services.AddAuthorization((options) =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
            // options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
        });

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);
        builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
        {
            options.SerializerOptions.WriteIndented = true;
        });

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.Map("/API", async (context) =>
        {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"API: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) =>
        {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"WhereAmI: API: {System.DateTime.Now:s}");
        });
        app.Map("/APIDump", async (HttpContext context) =>
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
        }).RequireAuthorization(
            new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()
            );

        app.MapControllers();

        app.Run();
    }
}
