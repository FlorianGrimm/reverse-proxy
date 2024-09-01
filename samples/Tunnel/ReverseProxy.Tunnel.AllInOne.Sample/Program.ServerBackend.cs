// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Brimborium.Extensions.Logging.LocalFile;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Tunnel;

namespace SampleServer;

internal partial class Program
{
    private static WebApplication ServerBackend(string[] args, string appsettingsFolder, string appsettingsPath)
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

            builder.Services.AddControllers()
                .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

            AuthenticationBuilder? authenticationBuilder = default;

            var reverseProxyBuilder = builder.Services.AddReverseProxy()
                .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
                .AddTunnelTransport(
                    configureTunnelHttp2: options =>
                    {
                        options.MaxConnectionCount = 1;
                        options.IsEnabled = enableTunnelH2;
                        options.ConfigureSocketsHttpHandlerAsync = (transportTunnelConfig, socketsHttpHandler, transportTunnelHttp2Authentication) =>
                        {
                            socketsHttpHandler.SslOptions.LocalCertificateSelectionCallback = (object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate? target, string[] acceptableIssuers) =>
                            {
                                return 0 < localCertificates.Count ? localCertificates[0] : null!;
                            };
                            socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback = (object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) =>
                            {
                                var result = sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                                if (!result)
                                {
                                    return false;
                                }
                                return result;
                            };
                            return ValueTask.CompletedTask;
                        };
                    },
                    configureTunnelWebSocket: options =>
                    {
                        options.MaxConnectionCount = 1;
                        options.IsEnabled = enableTunnelWS;
                        options.ConfigureClientWebSocket = (config, clientWebSocket) =>
                        {
                            if (config.Authentication.Mode == "ClientCertificate")
                            {
                                clientWebSocket.Options.RemoteCertificateValidationCallback = (object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) =>
                                {
                                    var result = sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                                    if (!result)
                                    {
                                        return false;
                                    }
                                    return result;
                                };
                            }
                        };
                    }
                );

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationAnonymous)
            {
                reverseProxyBuilder.AddTunnelTransportAnonymous();
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationNegotiate)
            {
                authenticationBuilder = authenticationBuilder ?? CreateAuthenticationBuilder(builder);
                authenticationBuilder.AddNegotiate();
                reverseProxyBuilder.AddTunnelTransportNegotiate();
            }
            else if (_browserAuthentication == BrowserAuthentication.Negotiate)
            {
                authenticationBuilder = authenticationBuilder ?? CreateAuthenticationBuilder(builder);
                authenticationBuilder.AddNegotiate();
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate)
            {
                reverseProxyBuilder
                    .AddTunnelTransportCertificate(
                        (options) =>
                        {
                            options.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13;
                        }
                    )
                    .ConfigureCertificateLoaderOptions(options =>
                    {
                        options.CertificateRoot = System.AppContext.BaseDirectory;
                    });
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationJwtBearer)
            {
                authenticationBuilder = authenticationBuilder ?? CreateAuthenticationBuilder(builder);
                authenticationBuilder.AddJwtBearer();
                reverseProxyBuilder.AddTunnelTransportJwtBearer();
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

            app.UseWebSockets();
            app.MapControllers();

            app.MapReverseProxy();

            app.MapGet("/Backend", (HttpContext context) =>
            {
                var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
                return $"Backend {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
            });
            return app;
        }
        catch (System.Exception error)
        {
            logger?.LogError(error, nameof(ServerBackend));
            System.Console.Error.WriteLine(error.ToString());
            throw;
        }
    }
}
