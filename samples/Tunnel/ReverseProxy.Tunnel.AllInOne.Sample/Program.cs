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

#if README
    This sample demonstrates how to use the tunnel feature of the reverse proxy.
    It starts multiple servers and tests the connection between them.

    https://localhost:5001 - https://localhost:5002 - Frontend Servers

    The frontend servers are configured to use the reverse proxy to tunnel the request to the backend servers.
    

    https://localhost:5003 - https://localhost:5004 - Backend Servers

    The backend servers are configured to use the reverse proxy to establish tunnel to the Frontend servers.
    The backend servers are configured to use the reverse proxy to foreward the request to the API servers.

    https://localhost:5005 - https://localhost:5006 - API Servers

    The api servers process the request and return the result - the request as html.

    The perfomance depend on the console logger (and the logging settings on the appsettings).
    You get better results if you are redirect the output to a file.

    cd ".\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0"
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2-a test measure stop
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-a test measure stop
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w test measure stop
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2-c test measure stop

    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w browser-windows test 
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w browser-windows test measure stop

    h2-a|h2-c|h2-w|h2ws-a|h2ws-w|ws-a|ws-c|ws-w]
    browser-windows
    browser-oauth
#endif

internal class Program
{

    private static ModeAppSettings _modeAppSettings = ModeAppSettings.H2Anonymous;
    private static BrowserAuthentication _browserAuthentication = BrowserAuthentication.Anonymous;
    private static TunnelAuthentication _modeTunnelAuthentication = TunnelAuthentication.AuthenticationAnonymous;
    private static bool enableTunnelH2 = false;
    private static bool enableTunnelWS = false;
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            System.Console.Out.WriteLine("Syntax: [h2-a|h2-c|h2-j|h2-w|h2ws-a|h2ws-w|ws-a|ws-c|ws-w] [browser-anonymous|browser-windows|browser-oauth] [1][2][3][4][5][6] [test] [measure] [stop]");
            System.Console.Out.WriteLine("Tunnel protocol-authentication");
            System.Console.Out.WriteLine("  h2-: HTTP/2");
            System.Console.Out.WriteLine("  ws-: WebSocket");
            System.Console.Out.WriteLine("  -a: Anonymous");
            System.Console.Out.WriteLine("  -c: Client Certificate authentication");
            System.Console.Out.WriteLine("  -w: Windows authentication");
            System.Console.Out.WriteLine("  -j: JwtBaerer");
            System.Console.Out.WriteLine("Browser Authentication:");
            System.Console.Out.WriteLine("browser-anonymous: browser wants no auth");
            System.Console.Out.WriteLine("browser-windows: browser wants windows auth");
            System.Console.Out.WriteLine("[1][2][3][4][5][6] which server to start none specified means all");
            System.Console.Out.WriteLine("test:     do some tests");
            System.Console.Out.WriteLine("measure: do some request and measure the time");
            System.Console.Out.WriteLine("stop:     after test and/or measure stop and don't wait for CTRL-C.");
        }

        var hsArgs = args.ToHashSet();
        var appsettingsFolder = ParseArgs(hsArgs);
        var (s1, s2, s3, s4, s5, s6) = (hsArgs.Remove("1"), hsArgs.Remove("2"), hsArgs.Remove("3"), hsArgs.Remove("4"), hsArgs.Remove("5"), hsArgs.Remove("6"));
        var (test, measure, wait) = (hsArgs.Remove("test"), hsArgs.Remove("measure"), !hsArgs.Remove("stop"));

        if (0 < hsArgs.Count)
        {
            System.Console.WriteLine($"Unknown args {string.Join(" ", hsArgs)}");
            return 1;
        }
        try
        {
            Console.Out.WriteLine("Starting Servers");
            Thread.CurrentThread.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo(1033);
            Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(1033);

            List<WebApplication> listWebApplication = [];

            Task taskRunServer;
            {
                var allServers = !s1 && !s2 && !s3 && !s4 && !s5 && !s6;

                if (allServers || s5) { listWebApplication.Add(ServerAPI(args, appsettingsFolder, "appsettings.server5API.json")); }
                if (allServers || s6) { listWebApplication.Add(ServerAPI(args, appsettingsFolder, "appsettings.server6API.json")); }

                if (allServers || s1) { listWebApplication.Add(ServerFrontend(args, appsettingsFolder, "appsettings.server1FE.json")); }
                if (allServers || s2) { listWebApplication.Add(ServerFrontend(args, appsettingsFolder, "appsettings.server2FE.json")); }

                if (allServers || s3) { listWebApplication.Add(ServerBackend(args, appsettingsFolder, "appsettings.server3BE.json")); }
                if (allServers || s4) { listWebApplication.Add(ServerBackend(args, appsettingsFolder, "appsettings.server4BE.json")); }

                var listTaskRun = new List<Task>();
                foreach (var webApplication in listWebApplication)
                {
                    TaskCompletionSource tcs = new();
                    var task = webApplication.RunAsync();
                    webApplication.Lifetime.ApplicationStarted.Register(() => { tcs.TrySetResult(); }, true);
                    await Task.Delay(50);
                    listTaskRun.Add(task);
                    await tcs.Task;
                }
                taskRunServer = listTaskRun.Count > 0 ? Task.WhenAll(listTaskRun) : Task.CompletedTask;

                // give the servers some time to start and establish the tunnels
                await Task.Delay(200);
            }

            if (test)
            {
                System.Console.Out.WriteLine("Starting Tests.");
                if (0 < await RunTests())
                {
                    return 1;
                }
                System.Console.Out.WriteLine("Done Tests.");
            }

            if (measure)
            {
                System.Console.Out.WriteLine("Starting measure.");
                await RunMeasurement();
                System.Console.Out.WriteLine("Done measure.");
            }

            if (wait)
            {
                System.Console.Error.WriteLine("Hit CTRL-C to exit.");
                await taskRunServer;
            }
            foreach (var app in listWebApplication)
            {
                await app.Services.GetRequiredService<Brimborium.Extensions.Logging.LocalFile.LocalFileLoggerProvider>().FlushAsync(CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
        return 0;
    }

    private static string ParseArgs(HashSet<string> hsArgs)
    {
        // tunnel 
        {
            var (
                h2_a, h2_c, h2_w, h2_j,
                h2ws_a, h2ws_w,
                ws_a, ws_c, ws_w) = (
                hsArgs.Remove("h2-a"), hsArgs.Remove("h2-c"), hsArgs.Remove("h2-w"), hsArgs.Remove("h2-j"),
                hsArgs.Remove("h2ws-a"), hsArgs.Remove("h2ws-w"),
                hsArgs.Remove("ws-a"), hsArgs.Remove("ws-c"), hsArgs.Remove("ws-w"));

            if (h2_a) { _modeAppSettings = ModeAppSettings.H2Anonymous; }
            else if (h2_c) { _modeAppSettings = ModeAppSettings.H2Certificate; }
            else if (h2_w) { _modeAppSettings = ModeAppSettings.H2Windows; }
            else if (h2_j) { _modeAppSettings = ModeAppSettings.H2JwtBaerer; }

            else if (h2ws_a) { _modeAppSettings = ModeAppSettings.H2WSAnonymous; }
            else if (h2ws_w) { _modeAppSettings = ModeAppSettings.H2WSWindows; }

            else if (ws_a) { _modeAppSettings = ModeAppSettings.WSAnonymous; }
            else if (ws_c) { _modeAppSettings = ModeAppSettings.WSCertificate; }
            else if (ws_w) { _modeAppSettings = ModeAppSettings.WSWindows; }

            else { _modeAppSettings = ModeAppSettings.H2Anonymous; }
        }

        // browser authentication
        {
            var browserWindows = hsArgs.Remove("browser-windows");
            var browserAnonymous = hsArgs.Remove("browser-anonymous");

            if (browserWindows)
            {
                _browserAuthentication = BrowserAuthentication.Windows;
            }
            else if (browserAnonymous)
            {
                _browserAuthentication = BrowserAuthentication.Anonymous;
            }
            else
            {
                _browserAuthentication = BrowserAuthentication.Anonymous;
            }
        }

        string appsettingsFolder;

        // tunnel / appsettings
        {
            if (_modeAppSettings == ModeAppSettings.H2Anonymous)
            {
                appsettingsFolder = "appsettings-H2-Anonymous";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationAnonymous;
                enableTunnelH2 = true;
            }
            else if (_modeAppSettings == ModeAppSettings.H2Certificate)
            {
                appsettingsFolder = "appsettings-H2-ClientCertificate";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationCertificate;
                enableTunnelH2 = true;
            }
            else if (_modeAppSettings == ModeAppSettings.H2Windows)
            {
                appsettingsFolder = "appsettings-H2-Windows";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationWindows;
                enableTunnelH2 = true;
            }
            else if (_modeAppSettings == ModeAppSettings.H2JwtBaerer)
            {
                appsettingsFolder = "appsettings-H2-JwtBaerer";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationJwtBearer;
                enableTunnelH2 = true;
            }
            else if (_modeAppSettings == ModeAppSettings.H2WSAnonymous)
            {
                appsettingsFolder = "appsettings-H2WS-Anonymous";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationAnonymous;
                enableTunnelH2 = true;
                enableTunnelWS = true;
            }
            else if (_modeAppSettings == ModeAppSettings.H2WSWindows)
            {
                appsettingsFolder = "appsettings-H2WS-Windows";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationWindows;
                enableTunnelH2 = true;
                enableTunnelWS = true;
            }
            else if (_modeAppSettings == ModeAppSettings.WSAnonymous)
            {
                appsettingsFolder = "appsettings-WS-Anonymous";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationAnonymous;
                enableTunnelWS = true;
            }
            else if (_modeAppSettings == ModeAppSettings.WSCertificate)
            {
                appsettingsFolder = "appsettings-WS-ClientCertificate";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationCertificate;
                enableTunnelWS = true;
            }
            else if (_modeAppSettings == ModeAppSettings.WSWindows)
            {
                appsettingsFolder = "appsettings-WS-Windows";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationWindows;
                enableTunnelWS = true;
            }
            else
            {
                throw new InvalidOperationException("modeAppSettings is unsupported.");
            }
        }
        appsettingsFolder = System.IO.Path.Combine(System.AppContext.BaseDirectory, appsettingsFolder);
        System.Console.WriteLine(appsettingsFolder);
        return appsettingsFolder;
    }

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

            builder.Services.AddAuthorization()
                .AddRouting()
                .AddEndpointsApiExplorer();
            
            builder.Services.AddControllers()
                .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

            var reverseProxyBuilder = builder.Services.AddReverseProxy()
                .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
                .AddTunnelServices(
                    options: new TunnelServicesOptions()
                    {
                        // Anonymous is dangerous - please read the documentation of TunnelServicesOptions and configure a proper authentication.
                        TunnelAuthenticationAnonymous = _modeTunnelAuthentication == TunnelAuthentication.AuthenticationAnonymous,
                        TunnelAuthenticationCertificate = _modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate,
                        TunnelAuthenticationWindows = _modeTunnelAuthentication == TunnelAuthentication.AuthenticationWindows,
                        TunnelHTTP2 = enableTunnelH2,
                        TunnelWebSocket = enableTunnelWS
                    }) // enable tunnel listener
                .ConfigureCertificateConfigOptions(options =>
                {
                    options.CertificateRoot = System.AppContext.BaseDirectory;
                });

            var authenticationBuilder = builder.Services.AddAuthentication(
                (AuthenticationOptions options) =>
                {
                    if (_browserAuthentication == BrowserAuthentication.Windows)
                    {
                        options.DefaultScheme = NegotiateDefaults.AuthenticationScheme;
                    }
                });

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate)
            {
                authenticationBuilder
                   .AddCertificate(options =>
                   {
                       // this sample uses the SelfSigned certificates.
                       options.AllowedCertificateTypes = CertificateTypes.SelfSigned;
                       options.RevocationMode = X509RevocationMode.NoCheck;
                       options.ValidateCertificateUse = false;
                       options.ValidateValidityPeriod = false;

                       // this allows other authenticationSchema to be used
                       options.Events = new CertificateAuthenticationEvents
                       {
                           OnCertificateValidated = context =>
                           {
                               if (context.ClientCertificate != null)
                               {
                                   context.Success();
                               }
                               else
                               {
                                   context.NoResult();
                               }
                               return Task.CompletedTask;
                           }
                       };
                   });

                // this sample uses the SelfSigned certificates so disable the some check.
                builder.WebHost.ConfigureKestrel(kestrelServerOptions =>
                {
                    kestrelServerOptions.ConfigureEndpointDefaults(listenOptions =>
                    {
                        listenOptions.UseHttps(ConfigHttpsConnectionAdapterOptions);
                    });
                    kestrelServerOptions.ConfigureHttpsDefaults(ConfigHttpsConnectionAdapterOptions);
                });
                static void ConfigHttpsConnectionAdapterOptions(HttpsConnectionAdapterOptions httpsConnectionAdapterOptions)
                {
                    httpsConnectionAdapterOptions.CheckCertificateRevocation = false;
                    httpsConnectionAdapterOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
                    httpsConnectionAdapterOptions.ClientCertificateValidation = (certificate, chain, sslPolicyErrors) =>
                    {
                        // return sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                        return true;
                    };
                }

                reverseProxyBuilder
                    .ConfigureTunnelAuthenticationCertificateOptions(
                         (tunnelAuthenticationCertificateOptions) =>
                         {
                             tunnelAuthenticationCertificateOptions.IgnoreSslPolicyErrors = SslPolicyErrors.RemoteCertificateChainErrors;
                         });
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationJwtBearer)
            {
                reverseProxyBuilder.AddTunnelAuthenticationJwtBearer(
                    builder.Configuration.GetRequiredSection("AzureAd")); // add custom JWT bearer authentication
            }

            if ((_browserAuthentication == BrowserAuthentication.Windows)
                || (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationWindows)
                )
            {
                authenticationBuilder.AddNegotiate(options => {
                    options.Events ??= new();
                    options.Events.OnAuthenticationFailed = (AuthenticationFailedContext context) =>
                    {
                        return Task.CompletedTask;
                    };
                });
            }

            builder.Services.AddAuthorization(
                (AuthorizationOptions options) =>
                {
                    if (_browserAuthentication == BrowserAuthentication.Windows)
                    {
                        options.AddPolicy("AuthenticatedUser", policy =>
                        {
                            policy.RequireAuthenticatedUser().AddAuthenticationSchemes(NegotiateDefaults.AuthenticationScheme);
                        });
                    }
                });


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
                if (_browserAuthentication == BrowserAuthentication.Windows)
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

            var authenticationBuilder = builder.Services.AddAuthentication(
                (options) =>
                {
                    if (_browserAuthentication == BrowserAuthentication.Windows)
                    {
                        options.DefaultScheme = NegotiateDefaults.AuthenticationScheme;
                    }
                });

            var reverseProxyBuilder = builder.Services.AddReverseProxy()
                .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
                .AddTunnelTransport(
                    options: new TransportTunnelOptions()
                    {
                        // This is dangerous - please read the documentation of TransportTunnelOptions and configure a proper authentication.
                        TunnelAuthenticationAnonymous = _modeTunnelAuthentication == TunnelAuthentication.AuthenticationAnonymous,
                        TunnelAuthenticationCertificate = _modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate,
                        TunnelAuthenticationWindows = _modeTunnelAuthentication == TunnelAuthentication.AuthenticationWindows
                    },
                    configureTunnelHttp2: options =>
                    {
                        options.MaxConnectionCount = 10;
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
                        options.MaxConnectionCount = 10;
                        options.IsEnabled = enableTunnelWS;
                        options.ConfigureClientWebSocket = (config, clientWebSocket, transportTunnelWebSocketAuthentication) =>
                        {
                            if (transportTunnelWebSocketAuthentication.GetAuthenticationName() == "ClientCertificate")
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
                ) /* for the servers that starts the tunnel transport connections */
                .ConfigureCertificateConfigOptions(options =>
                {
                    options.CertificateRoot = System.AppContext.BaseDirectory;
                });

            /*
                .ConfigureCertificateConfigOptions(
                    configure: (options) => {
                        options.CertificatePassword = (config) => {
                            return magic(config.Password);
                        };
                    });
            */

            if ((_modeTunnelAuthentication == TunnelAuthentication.AuthenticationWindows)
                || (_browserAuthentication == BrowserAuthentication.Windows))
            {
                authenticationBuilder.AddNegotiate();
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate)
            {
                authenticationBuilder.AddCertificate(options =>
                {
                    options.AllowedCertificateTypes = CertificateTypes.SelfSigned;
                }).AddCertificateCache();
            }

            if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationJwtBearer)
            {
                authenticationBuilder.AddJwtBearer();
                reverseProxyBuilder.AddTunnelTransportAuthenticationJwtBearer();
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

    private static async Task<int> RunTests()
    {

        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // Try to access Url directly
        try
        {
            await TestRequestGet("https://localhost:5001/Frontend", "Frontend https://localhost:5001/ - localhost:5001 -");
            await TestRequestGet("https://localhost:5003/Backend", "Backend https://localhost:5003/ - localhost:5003 -");
            await TestRequestGet("https://localhost:5005/API", "API https://localhost:5005/ - localhost:5005 -");

            //
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.ToString());
            if (error.InnerException is not null)
            {
                Console.Error.WriteLine(error.InnerException.ToString());
            }
            return 1;
        }
        //

        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // try tunnel - forward
        try
        {
            await TestRequestGet("https://localhost:5001/API", "API https://localhost:5005/ - localhost:5005 -");
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.ToString());
            if (error.InnerException is not null)
            {
                Console.Error.WriteLine(error.InnerException.ToString());
            }
            return 1;
        }
        //

        if (false && _modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate)
        {
            System.Console.WriteLine(System.DateTime.Now.ToString("s"));
            // localhostclient1.pfx - the right one
            {
                try
                {
                    // to test the certificate
                    // https://localhost:5001/_CheckCert
                    {
                        var testCertPfxPath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!, "localhostclient1.pfx");
                        var certificate = new X509Certificate2(testCertPfxPath, "testPassword1", X509KeyStorageFlags.PersistKeySet);
                        var socketsHttpHandler = CreateSocketsHttpHandler(certificate);
                        HttpClient httpClient = new(socketsHttpHandler);
                        var url = "https://localhost:5001/_CheckCert";
                        Console.Out.WriteLine($"Sending request to {url}");
                        var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
                        response.EnsureSuccessStatusCode();
                        var result = await response.Content.ReadAsStringAsync();
                        Console.Out.WriteLine($"Success: {result}");
                    }
                }
                catch (Exception error)
                {
                    Console.Error.WriteLine(error.ToString());
                    if (error.InnerException is not null)
                    {
                        Console.Error.WriteLine(error.InnerException.ToString());
                    }
                    return 1;
                }
            }

            // testCert.pfx (the wrong one)
            {
                try
                {
                    // to test the certificate
                    // https://localhost:5001/_CheckCert
                    {
                        var testCertPfxPath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!, "testCert.pfx");
                        var certificate = new X509Certificate2(testCertPfxPath, "testPassword", X509KeyStorageFlags.PersistKeySet);
                        var socketsHttpHandler = CreateSocketsHttpHandler(certificate);
                        HttpClient httpClient = new(socketsHttpHandler);

                        var url = "https://localhost:5001/_CheckCert";
                        Console.Out.WriteLine($"Sending request to {url}");
                        var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
                        response.EnsureSuccessStatusCode();
                        var result = await response.Content.ReadAsStringAsync();
                        Console.Out.WriteLine($"Failed: Request {response.StatusCode}: {result}");
                    }
                }
                catch (System.Net.Http.HttpRequestException error)
                {
                    if ((error.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                        || (error.StatusCode == System.Net.HttpStatusCode.Forbidden))
                    {
                        System.Console.Error.WriteLine($"Success expected StatusCode:{error.StatusCode}");
                    }
                    else
                    {
                        System.Console.Error.WriteLine($"Failed StatusCode:{error.StatusCode}");
                    }
                }
                catch (Exception error)
                {
                    Console.Error.WriteLine(error.ToString());
                    if (error.InnerException is not null)
                    {
                        System.Console.Error.WriteLine(error.InnerException.ToString());
                    }
                    return 1;
                }
            }
        }
        //

        return 0;
    }

    private static async Task TestRequestGet(string url, string expectedContent)
    {
        var socketsHttpHandler = new SocketsHttpHandler();
        socketsHttpHandler.ConnectTimeout = TimeSpan.FromSeconds(2);
        socketsHttpHandler.ResponseDrainTimeout = TimeSpan.FromSeconds(2);
        if (_browserAuthentication == BrowserAuthentication.Windows) {
            socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
        }
        

        using var httpClient = new HttpClient(socketsHttpHandler, true);
        Console.Out.WriteLine($"Sending request to {url}");
        var request = new HttpRequestMessage(HttpMethod.Get, url);

        using var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var result = await response.Content.ReadAsStringAsync();
        if (result.StartsWith(expectedContent))
        {
            Console.Out.WriteLine($"Success: {result}");
        }
        else
        {
            Console.Out.WriteLine($"Failed: {result}");
            throw new Exception($"Failed: {result}");
        }
    }


    private static async Task RunMeasurement()
    {
        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // little bit of speed measurment
        try
        {
            {
                TestSettings[] listTestSettings = [
                    new ("https://localhost:5001/Frontend"),
                        new ("https://localhost:5002/Frontend"),
                        new ("https://localhost:5001/Backend"),
                        new ("https://localhost:5002/Backend"),
                        new ("https://localhost:5001/API"),
                        new ("https://localhost:5002/API"),
                        new ("https://localhost:5001/alpha/API"),
                        new ("https://localhost:5002/beta/API"),
                        ];
                var startGlobal = Stopwatch.GetTimestamp();
                var cntloop = 20;
                for (var loop = 1; loop <= cntloop; loop++)
                {
                    Console.Out.WriteLine($"{loop} / {cntloop}");

                    for (var index = 0; index < listTestSettings.Length; index++)
                    {
                        var testSettings = listTestSettings[index];
                        var sw = Stopwatch.StartNew();
                        List<(HttpClient httpClient, Task<string> taskGetString)> listTask = new(20);

                        for (var innerloop = 0; innerloop < 20; innerloop++)
                        {
                            var socketsHttpHandler = CreateSocketsHttpHandler(null);
                            var client = new HttpClient(socketsHttpHandler, true);
                            var taskGetString = client.GetStringAsync(testSettings.Url);
                            listTask.Add((client, taskGetString));
                        }

                        foreach (var (client, taskGetString) in listTask)
                        {
                            var text = await taskGetString;
                            if (testSettings.Count.TryGetValue(text, out var count))
                            {
                                testSettings.Count[text] = count + 1;
                            }
                            else
                            {
                                testSettings.Count[text] = 1;
                            }
                            client.Dispose();
                        }
                        testSettings.Duration.Add(sw.ElapsedTicks);
                    }
                }

                var allTotalMilliseconds = TimeSpan.FromTicks(Stopwatch.GetTimestamp() - startGlobal).TotalMilliseconds;

                for (var index = 0; index < listTestSettings.Length; index++)
                {
                    var testSettings = listTestSettings[index];
                    var minDuration = TimeSpan.FromTicks(testSettings.Duration.Min()).TotalMilliseconds;
                    var maxDuration = TimeSpan.FromTicks(testSettings.Duration.Max()).TotalMilliseconds;
                    var averageDuration = TimeSpan.FromTicks(testSettings.Duration.Sum() / testSettings.Duration.Count).TotalMilliseconds;

                    Console.WriteLine($"{testSettings.Url} - {minDuration} / {averageDuration} / {maxDuration}");
                    foreach (var (content, count) in testSettings.Count.ToList().OrderBy(c => c.Key))
                    {
                        Console.WriteLine($"{count} - {content}");
                    }

                }
            }
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.ToString());
            if (error.InnerException is not null)
            {
                Console.Error.WriteLine(error.InnerException.ToString());
            }
        }
    }

    private static SocketsHttpHandler CreateSocketsHttpHandler(X509Certificate2? certificate = null)
    {
        var socketsHttpHandler = new SocketsHttpHandler();
        if ((_browserAuthentication == BrowserAuthentication.Windows)
            || (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationWindows))
        {
            socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
        }
        socketsHttpHandler.AllowAutoRedirect = false;
        socketsHttpHandler.EnableMultipleHttp2Connections = true;

        if (certificate is not null)
        {
            socketsHttpHandler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            (socketsHttpHandler.SslOptions.ClientCertificates ??= []).Add(certificate);
            socketsHttpHandler.SslOptions.LocalCertificateSelectionCallback
                = (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => certificate;
            socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback
                = (sender, targetHost, localCertificates, remoteCertificate) => true;
        }

        return socketsHttpHandler;
    }
}

internal enum ModeAppSettings
{
    H2Anonymous,
    H2Certificate,
    H2Windows,
    H2JwtBaerer,

    H2WSAnonymous,
    H2WSWindows,

    WSAnonymous,
    WSCertificate,
    WSWindows
}

internal enum BrowserAuthentication
{
    Anonymous,
    Windows
}

internal enum TunnelAuthentication
{
    AuthenticationAnonymous,
    AuthenticationCertificate,
    AuthenticationWindows,
    AuthenticationJwtBearer
}


internal record TestSettings(string Url)
{
    public readonly ConcurrentDictionary<string, int> Count = new();
    public readonly List<long> Duration = new(1000);
}
