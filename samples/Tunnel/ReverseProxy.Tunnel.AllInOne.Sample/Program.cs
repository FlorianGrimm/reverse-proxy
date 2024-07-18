// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Tunnel;

namespace SampleServer;

/*
    The perfomance depend on the console logger (and the logging settings on the appsettings).
    You get better results if you are redirect the output to a file.

    cd ".\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0"
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2-a 1 2 3 4 5 6 test measure >loga.txt
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-a 1 2 3 4 5 6 test measure >logb.txt
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w 1 2 3 4 5 6 test measure >logw.txt
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2-c 1 2 3 4 5 6 test measure >logc.txt

    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w authwin 1 2 3 4 5 6 test wait
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w authwin 1 2 3 4 5 6 test measure >logww.txt

 */

internal class Program
{

    private static ModeAppSettings modeAppSettings = ModeAppSettings.H2Anonymous;
    private static BrowserAuthentication browserAuthentication = BrowserAuthentication.Anonymous;
    private static TunnelAuthentication modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationAnonymous;

    private static async Task Main(string[] args)
    {
        var hsArgs = args.ToHashSet();
        System.Console.Out.WriteLine("Syntax: [h2-a|h2-c|h2-w|h2ws-a|h2ws-w|ws-a|ws-c|ws-w] [authwin] [1][2][3][4][5][6] [test] [meassure] [wait]");

        var appsettingsFolder = "";
        // tunnel 
        {
            var (
                h2_a, h2_c, h2_w,
                h2ws_a, h2ws_w,
                ws_a, ws_c, ws_w) = (
                hsArgs.Remove("h2-a"), hsArgs.Remove("h2-c"), hsArgs.Remove("h2-w"),
                hsArgs.Remove("h2ws-a"), hsArgs.Remove("h2ws-w"),
                hsArgs.Remove("ws-a"), hsArgs.Remove("ws-c"), hsArgs.Remove("ws-w"));
            if (h2_a) { modeAppSettings = ModeAppSettings.H2Anonymous; }
            else if (h2_c) { modeAppSettings = ModeAppSettings.H2Certificate; }
            else if (h2_w) { modeAppSettings = ModeAppSettings.H2Windows; }
#warning does not work
            else if (h2ws_a) { modeAppSettings = ModeAppSettings.H2WSAnonymous; }
            else if (h2ws_w) { modeAppSettings = ModeAppSettings.H2WSWindows; }
            else if (ws_a) { modeAppSettings = ModeAppSettings.WSAnonymous; }
            else if (ws_c) { modeAppSettings = ModeAppSettings.WSWindows; }
            else if (ws_w) { modeAppSettings = ModeAppSettings.WSWindows; }
            else { modeAppSettings = ModeAppSettings.H2Anonymous; }
        }

        // browser authentication
        {
            var authwin = hsArgs.Remove("authwin");
            if (authwin)
            {
                browserAuthentication = BrowserAuthentication.Windows;
            }
            else
            {
                browserAuthentication = BrowserAuthentication.Anonymous;
            }
        }

        // tunnel / appsettings
        {
            if (modeAppSettings == ModeAppSettings.H2Anonymous)
            {
                appsettingsFolder = "appsettings-H2-Anonymous";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationAnonymous;
            }
            else if (modeAppSettings == ModeAppSettings.H2Certificate)
            {
                appsettingsFolder = "appsettings-H2-ClientCertificate";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationCertificate;
            }
            else if (modeAppSettings == ModeAppSettings.H2Windows)
            {
                appsettingsFolder = "appsettings-H2-Windows";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationWindows;
            }
            else if (modeAppSettings == ModeAppSettings.H2WSAnonymous)
            {
                appsettingsFolder = "appsettings-H2WS-Anonymous";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationAnonymous;
            }
            else if (modeAppSettings == ModeAppSettings.H2WSWindows)
            {
                appsettingsFolder = "appsettings-H2WS-Windows";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationWindows;
            }
            else if (modeAppSettings == ModeAppSettings.WSAnonymous)
            {
                appsettingsFolder = "appsettings-WS-Anonymous";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationAnonymous;
            }
            else if (modeAppSettings == ModeAppSettings.WSCertificate)
            {
                appsettingsFolder = "appsettings-WS-ClientCertificate";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationCertificate;
            }
            else if (modeAppSettings == ModeAppSettings.WSWindows)
            {
                appsettingsFolder = "appsettings-WS-Windows";
                modeTunnelAuthentiacation = TunnelAuthentication.AuthenticationWindows;
            }
            else
            {
                throw new InvalidOperationException("modeAppSettings is unsupported.");
            }
        }

        appsettingsFolder = System.IO.Path.Combine(System.AppContext.BaseDirectory, appsettingsFolder);

        try
        {
            Console.Out.WriteLine("Starting Servers");
            Thread.CurrentThread.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo(1033);
            Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(1033);

            List<WebApplication> listWebApplication = [];


            Task taskRunServer;
            {
                var (s1, s2, s3, s4, s5, s6) = (hsArgs.Remove("1"), hsArgs.Remove("2"), hsArgs.Remove("3"), hsArgs.Remove("4"), hsArgs.Remove("5"), hsArgs.Remove("6"));
                var sall = !s1 && !s2 && !s3 && !s4 && !s5 && !s6;
                if (sall || s1) { listWebApplication.Add(ServerFrontend(args, appsettingsFolder, "appsettings.server1FE.json")); }
                if (sall || s2) { listWebApplication.Add(ServerFrontend(args, appsettingsFolder, "appsettings.server2FE.json")); }
                if (sall || s3) { listWebApplication.Add(ServerBackend(args, appsettingsFolder, "appsettings.server3BE.json")); }
                if (sall || s4) { listWebApplication.Add(ServerBackend(args, appsettingsFolder, "appsettings.server4BE.json")); }
                if (sall || s5) { listWebApplication.Add(ServerAPI(args, appsettingsFolder, "appsettings.server5API.json")); }
                if (sall || s6) { listWebApplication.Add(ServerAPI(args, appsettingsFolder, "appsettings.server6API.json")); }

                var listTaskRun = listWebApplication.Select(app => app.RunAsync()).ToList();
                taskRunServer = listTaskRun.Count > 0 ? Task.WhenAll(listTaskRun) : Task.CompletedTask;
            }

            var (test, meassure, wait) = (hsArgs.Remove("test"), hsArgs.Remove("meassure"), hsArgs.Remove("wait"));
            if (!test && !meassure && !wait) { test = wait = true; }
            if (test)
            {
                System.Console.Out.WriteLine("Starting Tests.");
                await RunTests();
                System.Console.Out.WriteLine("Done Tests.");
            }

            if (meassure)
            {
                System.Console.Out.WriteLine("Starting meassure.");
                await RunMeassurement();
                System.Console.Out.WriteLine("Done meassure.");
                /*
                    https://localhost:5001/Frontend - 9.7654 / 13.8606 / 17.9559
                    40 - Frontend https://localhost:5001/ - localhost:5001 - ::1:5001
                    https://localhost:5002/Frontend - 8.1592 / 9.9624 / 11.7656
                    40 - Frontend https://localhost:5002/ - localhost:5002 - ::1:5002
                    https://localhost:5001/Backend - 13.7075 / 15.1062 / 16.505
                    17 - Backend https://localhost:5003/ - alpha - :0
                    23 - Backend https://localhost:5004/ - alpha - :0
                    https://localhost:5002/Backend - 12.8154 / 32.6246 / 52.4339
                    22 - Backend https://localhost:5003/ - alpha - :0
                    18 - Backend https://localhost:5004/ - alpha - :0
                    https://localhost:5001/API - 13.9565 / 14.4115 / 14.8666
                    40 - API https://localhost:5005/ - localhost:5005 - ::1:5005
                    https://localhost:5002/API - 15.855 / 17.4957 / 19.1365
                    40 - API https://localhost:5005/ - localhost:5005 - ::1:5005
                    https://localhost:5001/alpha/API - 15.8263 / 16.3247 / 16.8232
                    40 - API https://localhost:5005/ - localhost:5005 - ::1:5005
                    https://localhost:5002/beta/API - 18.8477 / 19.2851 / 19.7225
                    40 - API https://localhost:5006/ - localhost:5006 - ::1:5006
                 */
            }

            if (wait)
            {
                System.Console.Error.WriteLine("Hit CTRL-C to exit.");
                await taskRunServer;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
        }
    }

    private static WebApplication ServerFrontend(string[] args, string appsettingsFolder, string appsettingsPath)
    {
        var appsettingsFullname = System.IO.Path.Combine(appsettingsFolder, appsettingsPath);

        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddJsonFile(appsettingsFullname, false, true);
        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);

        builder.Services.AddOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions>().BindConfiguration("AzureAd");

        builder.Services.AddAuthorization(options =>
            {
                //    options.FallbackPolicy = new AuthorizationPolicyBuilder()
                //        .RequireAuthenticatedUser()
                //        .Build();
            })
            .AddRouting()
            .AddEndpointsApiExplorer();

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

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelServices() // enable tunnel listener
            .ConfigureCertificateConfigOptions(options =>
            {
                options.CertificateRoot = System.AppContext.BaseDirectory;
            });

        // if (modeTunnelAuthentiacation == TunnelAuthentication.AuthenticationAnonymous) { }

        if (modeTunnelAuthentiacation == TunnelAuthentication.AuthenticationCertificate)
        {

            authenticationBuilder
               .AddCertificate(options =>
               {
                   options.AllowedCertificateTypes = CertificateTypes.SelfSigned;
                   options.RevocationMode = X509RevocationMode.NoCheck;
                   options.ValidateCertificateUse = false;
                   options.ValidateValidityPeriod = false;

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

            builder.WebHost.ConfigureKestrel(kestrelServerOptions =>
            {
                kestrelServerOptions.ConfigureEndpointDefaults(listenOptions =>
                {
                    listenOptions.UseHttps(o => o.AllowAnyClientCertificate());
                });
                kestrelServerOptions.ConfigureHttpsDefaults(
                    httpsConnectionOptions =>
                    {
                        httpsConnectionOptions.AllowAnyClientCertificate();
                        // httpsConnectionOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
                        httpsConnectionOptions.CheckCertificateRevocation = false;
                        httpsConnectionOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                    });
            });

            reverseProxyBuilder
                .ConfigureTunnelAuthenticationCertificateOptions(
                     (tunnelAuthenticationCertificateOptions) =>
                    {
                        tunnelAuthenticationCertificateOptions.IgnoreSslPolicyErrors = SslPolicyErrors.RemoteCertificateChainErrors;
                    });

        }

        if (modeTunnelAuthentiacation == TunnelAuthentication.AuthenticationWindows)
        {
            // dont add it twice
            if (browserAuthentication != BrowserAuthentication.Windows)
            {
                authenticationBuilder.AddNegotiate();
            }
        }

        builder.Services.AddAuthorization(
            options =>
            {
                if (browserAuthentication != BrowserAuthentication.Anonymous)
                {
                    options.AddPolicy("AuthenticatedUser", policy =>
                    {
                        policy.RequireAuthenticatedUser();
                    });
                }
                options.AddPolicy("RequireCertificate", policy =>
                {
                    policy.AuthenticationSchemes.Add(CertificateAuthenticationDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                });
            });


        var app = builder.Build();

        app.UseRouting()
            .UseAuthentication()
            .UseAuthorization();

        app.MapGet("/_CheckCert", async (context) =>
        {
            var certificate = await context.Connection.GetClientCertificateAsync();
            if (certificate is null)
            {
                await context.Response.WriteAsync("Hello no cert!");
            }
            else
            {
                await context.Response.WriteAsync("Hello cret!");
            }

        });
        //.RequireAuthorization("RequireCertificate");

        app.MapReverseProxy();
        app.UseWebSockets();
        app.MapControllers();

        {
            var route = app.MapGet("/Frontend", (HttpContext context) =>
            {
                var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
                return $"Frontend {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
            });
            if (browserAuthentication == BrowserAuthentication.Windows)
            {
                route.RequireAuthorization("AuthenticatedUser");
            }
        }

        return app;
    }

    private static WebApplication ServerBackend(string[] args, string appsettingsFolder, string appsettingsPath)
    {
        var appsettingsFullname = System.IO.Path.Combine(appsettingsFolder, appsettingsPath);

        var builder = WebApplication.CreateBuilder(args);

        builder.Configuration.AddJsonFile(appsettingsFullname, false, true);
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        builder.Configuration.AddUserSecrets("ReverseProxy");

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        builder.Services.AddOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions>().BindConfiguration("AzureAd");

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

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport(
                configureTunnelHttp2: options => { options.MaxConnectionCount = 10; },
                configureTunnelWebSocket: options => { options.MaxConnectionCount = 10; }
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

        if (modeTunnelAuthentiacation == TunnelAuthentication.AuthenticationWindows)
        {
            // don' add it twice
            if (browserAuthentication != BrowserAuthentication.Windows)
            {
                authenticationBuilder.AddNegotiate();
            }
        }

        var app = builder.Build();
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

    private static WebApplication ServerAPI(string[] args, string appsettingsFolder, string appsettingsPath)
    {
        var appsettingsFullname = System.IO.Path.Combine(appsettingsFolder, appsettingsPath);

        var builder = WebApplication.CreateBuilder(args);

        builder.Configuration.AddJsonFile(appsettingsFullname, false, true);
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);

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

    private static async Task RunTests()
    {

        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // Try to access Url directly
        try
        {
            // https://localhost:5001/Frontend
            {
                var socketsHttpHandler = CreateSocketsHttpHandler();
                using HttpClient httpClient = new(socketsHttpHandler, true);
                var url = "https://localhost:5001/Frontend";
                Console.Out.WriteLine($"Sending request to {url}");
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var response = await httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadAsStringAsync();
                if (result.StartsWith("Frontend https://localhost:5001/ - localhost:5001 -"))
                {
                    Console.Out.WriteLine($"Success: {result}");
                }
                else
                {
                    Console.Out.WriteLine($"Failed: {result}");
                }
            }

            // https://localhost:5003/Backend
            {
                var socketsHttpHandler = CreateSocketsHttpHandler();
                using HttpClient httpClient = new(socketsHttpHandler, true);
                var url = "https://localhost:5003/Backend";
                Console.Out.WriteLine($"Sending request to {url}");
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var response = await httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadAsStringAsync();
                if (result.StartsWith("Backend https://localhost:5003/ - localhost:5003 -"))
                {
                    Console.Out.WriteLine($"Success: {result}");
                }
                else
                {
                    Console.Out.WriteLine($"Failed: {result}");
                }
            }

            // https://localhost:5005/API
            {
                var socketsHttpHandler = CreateSocketsHttpHandler();

                using HttpClient httpClient = new(socketsHttpHandler, true);
                var url = "https://localhost:5005/API";
                Console.Out.WriteLine($"Sending request to {url}");
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var response = await httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadAsStringAsync();
                if (result.StartsWith("API https://localhost:5005/ - localhost:5005 -"))
                {
                    Console.Out.WriteLine($"Success: {result}");
                }
                else
                {
                    Console.Out.WriteLine($"Failed: {result}");
                }
            }
            //
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error.ToString());
            if (error.InnerException is not null)
            {
                Console.Error.WriteLine(error.InnerException.ToString());
            }
        }
        //

        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // try tunnel - forward
        try
        {
            // https://localhost:5001/API
            {
                var socketsHttpHandler = CreateSocketsHttpHandler(); ;

                using HttpClient httpClient = new(socketsHttpHandler, true);
                //httpClient.Timeout = TimeSpan.FromSeconds(2);
                var url = "https://localhost:5001/API";
                Console.Out.WriteLine($"Sending request to {url}");
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var response = await httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();
                var result = await response.Content.ReadAsStringAsync();
                if (result.Contains("API https://localhost:5005/ - localhost:5005 -"))
                {
                    Console.Out.WriteLine($"Success: {result}");
                }
                else
                {
                    Console.Out.WriteLine($"Failed: {result}");
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
        //

        if (modeTunnelAuthentiacation == TunnelAuthentication.AuthenticationCertificate)
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
                }
            }
        }
    }

    private static async Task RunMeassurement()
    {
        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // little bit of speed meassurment
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
        if ((browserAuthentication == BrowserAuthentication.Windows)
            || (modeTunnelAuthentiacation == TunnelAuthentication.AuthenticationWindows))
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
    AuthenticationWindows
}


internal record TestSettings(string Url)
{
    public readonly ConcurrentDictionary<string, int> Count = new();
    public readonly List<long> Duration = new(1000);
}
