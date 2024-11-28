namespace ReverseProxy.Tunnel.API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddAuthentication()
            ;

        builder.Logging.AddConsole();

        builder.Services.AddControllers()
                    .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);
        builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
        {
            options.SerializerOptions.WriteIndented = true;
        });

        builder.Services
            .AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport()
            .AddTunnelTransportCertificate(
                configuration: builder.Configuration.GetSection("ReverseProxy:AuthenticationCertificate"))
            .AddCertificateManager(
               configuration: builder.Configuration.GetSection("CertificateManager"),
               configure: (options) => { }
            )
            ;

        var app = builder.Build();

        // Using
        // app.UseHttpsRedirection();
        // stops the tunnel to work.
        // The request comes from the normal HTTPS - endpoint
        // AND from the TunnelTransport HTTP - endpoint.
        app.UseWhen(
            static (context) => !context.IsTransportTunnelRequest(),
            static (app) => app.UseHttpsRedirection());

        //app.UseAuthorization();
        //app.UseAuthentication();

        app.Map("/Backend", async (context) =>
        {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"Backend: {System.DateTime.Now:s}");
        });
        app.Map("/WhereAmI", async (context) =>
        {
            context.Response.Headers.ContentType = "text/plain";
            await context.Response.WriteAsync($"WhereAmI: Backend: {System.DateTime.Now:s}");
        });
        app.Map("/BackendDump", async (HttpContext context) =>
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
