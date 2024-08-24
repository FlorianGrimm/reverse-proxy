// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Brimborium.Extensions.Logging.LocalFile;

namespace SampleServer;

internal partial class Program
{
    private static WebApplication ServerAPI(string[] args, string appsettingsFolder, string appsettingsPath)
    {
        ILogger? logger = default;
        try
        {
            var appsettingsFullName = System.IO.Path.Combine(appsettingsFolder, appsettingsPath);

            var builder = WebApplication.CreateBuilder(args);

            builder.Configuration.AddJsonFile(appsettingsFullName, false, true);
            builder.Logging.ClearProviders();
            builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
            builder.Services.AddOptions<LocalFileLoggerOptions>().Configure(options =>
            {
                options.LogDirectory = System.IO.Path.Combine(System.AppContext.BaseDirectory, "LogFiles");
            });

            builder.Services.AddControllers()
                .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

            /*
            Microsoft.AspNetCore.Authentication.AuthenticationBuilder authenticationBuilder;
            if (browserAuthentication == BrowserAuthentication.Windows)
            {
                authenticationBuilder = builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme);
                authenticationBuilder.AddNegotiate();
            }
            else
            {
                authenticationBuilder = builder.Services.AddAuthentication();
            }
            */

            var app = builder.Build();
            app.Services.GetRequiredService<Brimborium.Extensions.Logging.LocalFile.LocalFileLoggerProvider>().HandleHostApplicationLifetime(app.Services.GetRequiredService<IHostApplicationLifetime>());
            logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Program");
            logger.LogInformation("start {args}", string.Join(" ", args));

            app.UseWebSockets();
            app.MapControllers();
            app.MapGet("/API", (HttpContext context) =>
            {
                var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
                return $"API {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
            });
            app.MapGet("/alpha/API", (HttpContext context) =>
            {
                var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
                return $"API {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
            });
            app.MapGet("/beta/API", (HttpContext context) =>
            {
                var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
                return $"API {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
            });

            return app;
        }
        catch (System.Exception error)
        {
            logger?.LogError(error, nameof(ServerAPI));
            System.Console.Error.WriteLine(error.ToString());
            throw;
        }
    }
}
