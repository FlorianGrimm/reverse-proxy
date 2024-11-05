// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Brimborium.Extensions.Logging.LocalFile;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;

using Yarp.ReverseProxy.Tunnel;

namespace SampleServer;

internal partial class Program
{
    private static WebApplication ServerFrontend(string[] args, string appsettingsFolder, string appsettingsPath)
    {
        ILogger? logger = default;
        try
        {
            var appsettingsFullName = System.IO.Path.Combine(appsettingsFolder, appsettingsPath);


            var builder = WebApplication.CreateBuilder(args);
            builder.Configuration.AddJsonFile(appsettingsFullName, false, true);
            builder.Configuration.AddUserSecrets("ReverseProxy");

            builder.Logging.ClearProviders();
            builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
            builder.Services.AddOptions<LocalFileLoggerOptions>().Configure(options =>
            {
                options.LogDirectory = System.IO.Path.Combine(System.AppContext.BaseDirectory, "LogFiles");
            });

            builder.Services
                .AddRouting()
                .AddEndpointsApiExplorer();

            builder.Services.AddControllers()
                .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

            AuthenticationBuilder? authenticationBuilder = default;

            var reverseProxyBuilder = builder.Services.AddReverseProxy()
                .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
                .AddTunnelServices(
                    new TunnelServicesOptions()
                    {
                        TunnelHTTP2 = enableTunnelH2,
                        TunnelWebSocket = enableTunnelWS
                    }
                ) // enable tunnel listener
                .ConfigureReverseProxyCertificateManager(configure:(options) =>
                {
                    options.CertificateRootPath = System.AppContext.BaseDirectory;
                });

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationAnonymous) {
                reverseProxyBuilder.AddTunnelServicesAnonymous();
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate)
            {
                reverseProxyBuilder
                    .AddTunnelServicesCertificate(
                         (options) =>
                         {
                             options.CheckCertificateRevocation = false;
                             options.AllowedCertificateTypes = CertificateTypes.All;
                             options.RevocationMode = X509RevocationMode.NoCheck;
                             options.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                             options.IgnoreSslPolicyErrors = SslPolicyErrors.RemoteCertificateChainErrors;
                         });
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationJwtBearer)
            {
                reverseProxyBuilder.AddTunnelServicesJwtBearer(
                    builder.Configuration.GetRequiredSection("AzureAd")); // add custom JWT bearer authentication
            }

            if ((_browserAuthentication == BrowserAuthentication.Negotiate)
                || (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationNegotiate)
                )
            {
                authenticationBuilder = authenticationBuilder ?? CreateAuthenticationBuilder(builder);
                authenticationBuilder.AddNegotiate(options =>
                {
                    options.Events ??= new();
                    options.Events.OnAuthenticationFailed = (AuthenticationFailedContext context) =>
                    {
                        return Task.CompletedTask;
                    };
                });
                reverseProxyBuilder.AddTunnelServicesNegotiate();
            }

            if (authenticationBuilder is { }) {
                builder.Services.AddAuthorization(
                    (AuthorizationOptions options) =>
                    {
                        if (_browserAuthentication == BrowserAuthentication.Negotiate)
                        {
                            options.AddPolicy("AuthenticatedUser", policy =>
                            {
                                policy.RequireAuthenticatedUser().AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
                            });
                        }
                    });
            }


            var app = builder.Build();
            app.Services.GetRequiredService<Brimborium.Extensions.Logging.LocalFile.LocalFileLoggerProvider>().HandleHostApplicationLifetime(app.Services.GetRequiredService<IHostApplicationLifetime>());
            logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Program");
            logger.LogInformation("start {args}", string.Join(" ", args));

            // app.UseHttpsRedirection() will redirect if the request is a tunnel request;
            // which means that the browser is redirected to https://{tunnelId}/... which is not what we want.
            app.UseWhen(
                static context => !context.TryGetTransportTunnelByUrl(out var _),
                app => app.UseHttpsRedirection()
            );

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapReverseProxy();
            app.UseWebSockets();
            app.MapControllers();

            {
                // shows information about the client certificate
                app.MapGet("/_CheckCert", async (context) =>
                {
                    var certificate = await context.Connection.GetClientCertificateAsync();
                    if (certificate is null)
                    {
                        await context.Response.WriteAsync("no certificate!");
                    }
                    else
                    {
                        await context.Response.WriteAsync($"certificate:{certificate.FriendlyName}");
                    }
                });
            }

            {
                var route = app.MapGet("/Frontend", (HttpContext context) =>
                {
                    var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
                    return $"Frontend {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
                });
                if (_browserAuthentication == BrowserAuthentication.Negotiate)
                {
                    route.RequireAuthorization("AuthenticatedUser");
                }
            }

            return app;
        }
        catch (System.Exception error)
        {
            logger?.LogError(error, nameof(ServerFrontend));
            System.Console.Error.WriteLine(error.ToString());
            throw;
        }
    }

    private static AuthenticationBuilder CreateAuthenticationBuilder(WebApplicationBuilder builder)
    {
        return builder.Services.AddAuthentication(
            (AuthenticationOptions options) =>
            {
                if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationNegotiate) {
                    options.DefaultScheme = NegotiateDefaults.AuthenticationScheme;
                }
                if (_browserAuthentication == BrowserAuthentication.Negotiate)
                {
                    options.DefaultScheme = NegotiateDefaults.AuthenticationScheme;
                } 
            });
    }
}
