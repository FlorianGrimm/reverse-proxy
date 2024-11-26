using Microsoft.AspNetCore.Authorization;

namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Logging.AddConsole();

        builder.Services.AddAuthentication(
            configureOptions: (options) =>
            {
                //options.DefaultAuthenticateScheme = Yarp.ReverseProxy.Authentication.TransportJwtBearerTokenDefaults.AuthenticationScheme;
                //options.DefaultScheme = Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                //options.DefaultAuthenticateScheme = Yarp.ReverseProxy.Authentication.TransportJwtBearerTokenDefaults.AuthenticationScheme;
                //options.DefaultChallengeScheme = Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                options.DefaultScheme = "switch";
                options.DefaultChallengeScheme = "switch";
            }
            )
            .AddTransportJwtBearerToken(
                configuration: builder.Configuration.GetSection("ReverseProxy:TransportJwtBearerToken"),
                configure: (options) =>
                {
                    //options.ForwardChallenge = Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                    //options.ForwardSignIn = Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                })
            .AddNegotiate()
            .AddPolicyScheme("switch", "switch", configureOptions: (options) =>
            {
                options.ForwardDefaultSelector = (context) =>
                {
                    try
                    {
                        var bearerToken = TransportJwtBearerTokenExtensions.GetBearerToken(context.Request.Headers.Authorization);
                        if (bearerToken is null)
                        {
                            return Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                        }
                        else
                        {
                            return Yarp.ReverseProxy.Authentication.TransportJwtBearerTokenDefaults.AuthenticationScheme;
                        }
                    }
                    catch
                    {
                        return Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
                    }
                };
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
