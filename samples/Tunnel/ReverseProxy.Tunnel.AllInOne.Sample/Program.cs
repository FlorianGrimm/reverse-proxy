// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication.Certificate;

using Yarp.ReverseProxy.Tunnel;

namespace SampleServer;

/*
    The perfomance depend on the console logger (and the logging settings on the appsettings).
    You get better results if you are redirect the output to a file.

    cd ".\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0"
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" a >loga.txt
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" w >logw.txt
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" c >logc.txt

 */

internal class Program
{

    private static ModeAppSettings ModeSettings = ModeAppSettings.H2Anonymous;
    private static ModeAuthentication ModeAuth = ModeAuthentication.AuthenticationAnonymous;

    private static async Task Main(string[] args)
    {
        System.Console.Out.WriteLine("Syntax: [a|A|c|w] [1][2][3][4][5][6][test]");

        var appsettingsFolder = "";

        if (args is { Length: > 0 } && args[0] == "c")
        {
            args = args.AsSpan(1).ToArray();
            ModeSettings = ModeAppSettings.H2Certificate;
        }
        else if (args is { Length: > 0 } && args[0] == "w")
        {
            args = args.AsSpan(1).ToArray();
            ModeSettings = ModeAppSettings.H2WSWindows;
        }
        else if (args is { Length: > 0 } && args[0] == "A")
        {
            args = args.AsSpan(1).ToArray();
            ModeSettings = ModeAppSettings.H2WSAnonymous;
        }
        else if (args is { Length: > 0 } && args[0] == "a")
        {
            args = args.AsSpan(1).ToArray();
            ModeSettings = ModeAppSettings.H2Anonymous;
        }
        else
        {
            ModeSettings = ModeAppSettings.H2Anonymous;
        }

        if (ModeSettings == ModeAppSettings.H2Certificate)
        {
            appsettingsFolder = "appsettings-H2-ClientCertificate";
            ModeAuth = ModeAuthentication.AuthenticationCertificate;
        }
        else if (ModeSettings == ModeAppSettings.H2Certificate)
        {
            appsettingsFolder = "appsettings-H2WS-Windows";
            ModeAuth = ModeAuthentication.AuthenticationWindows;
        }
        else if (ModeSettings == ModeAppSettings.H2WSAnonymous)
        {
            appsettingsFolder = "appsettings-H2WS-Anonymous";
            ModeAuth = ModeAuthentication.AuthenticationAnonymous;
        }
        else if (ModeSettings == ModeAppSettings.H2Anonymous)
        {
            appsettingsFolder = "appsettings-H2-Anonymous";
            ModeAuth = ModeAuthentication.AuthenticationAnonymous;
        }
        else
        {
            appsettingsFolder = "appsettings-H2-Anonymous";
            ModeAuth = ModeAuthentication.AuthenticationAnonymous;
        }
        appsettingsFolder = System.IO.Path.Combine(System.AppContext.BaseDirectory, appsettingsFolder);

        try
        {
            Console.Out.WriteLine("Starting Servers");
            Thread.CurrentThread.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo(1033);
            Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(1033);

            List<WebApplication> listWebApplication = [];
            var all = args.Length == 0;

            if (all || args.Contains("1")) { listWebApplication.Add(ServerFrontend(args, appsettingsFolder, "appsettings.server1FE.json")); }
            if (all || args.Contains("2")) { listWebApplication.Add(ServerFrontend(args, appsettingsFolder, "appsettings.server2FE.json")); }
            if (all || args.Contains("3")) { listWebApplication.Add(ServerBackend(args, appsettingsFolder, "appsettings.server3BE.json")); }
            if (all || args.Contains("4")) { listWebApplication.Add(ServerBackend(args, appsettingsFolder, "appsettings.server4BE.json")); }
            if (all || args.Contains("5")) { listWebApplication.Add(ServerAPI(args, appsettingsFolder, "appsettings.server5API.json")); }
            if (all || args.Contains("6")) { listWebApplication.Add(ServerAPI(args, appsettingsFolder, "appsettings.server6API.json")); }

            var listTaskRun = listWebApplication.Select(app => app.RunAsync()).ToList();
            var taskRun = listTaskRun.Count > 0 ? Task.WhenAll(listTaskRun) : Task.CompletedTask;

            if (all || args.Contains("test"))
            {
                System.Console.Out.WriteLine("Starting Tests.");
                await RunTests();
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

                System.Console.Out.WriteLine("Done Tests.");
            }

            System.Console.Error.WriteLine("Hit CTRL-C to exit.");
            await taskRun;
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

        var authenticationBuilder = builder.Services.AddAuthentication();

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelServices();

        if (ModeAuth == ModeAuthentication.AuthenticationAnonymous)
        {
        }

        if (ModeAuth == ModeAuthentication.AuthenticationCertificate)
        {

            builder.Services.AddAuthentication()
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

            builder.Services.AddAuthorization(
                options =>
                {
                    options.AddPolicy("RequireCertificate", policy =>
                    {
                        policy.AuthenticationSchemes.Add(CertificateAuthenticationDefaults.AuthenticationScheme);
                        policy.RequireAuthenticatedUser();
                    });
                });

            reverseProxyBuilder
                .AddTunnelServicesAuthenticationCertificate(
                    allowAnyClientCertificate: true,
                    //configureCertificateAuthenticationOptions: (certificateAuthenticationOptions) =>
                    //{
                    //    // for local self signed certs
                    //    //certificateAuthenticationOptions.AllowedCertificateTypes = CertificateTypes.SelfSigned;
                    //    certificateAuthenticationOptions.AllowedCertificateTypes = CertificateTypes.All;
                    //    certificateAuthenticationOptions.RevocationMode = X509RevocationMode.NoCheck;
                    //    certificateAuthenticationOptions.ValidateCertificateUse = false;
                    //    certificateAuthenticationOptions.ValidateValidityPeriod = false;
                    //    certificateAuthenticationOptions.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                    //},
                    configureTunnelAuthenticationCertificateOptions: (tunnelAuthenticationCertificateOptions) =>
                    {
                        tunnelAuthenticationCertificateOptions.IgnoreSslPolicyErrors = SslPolicyErrors.RemoteCertificateChainErrors;
                    },
                    configureKestrelServerOptions: (kestrelServerOptions) =>
                    {
                        kestrelServerOptions.ConfigureHttpsDefaults(
                            httpsOptions =>
                            {
                                httpsOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
                                httpsOptions.CheckCertificateRevocation = false;
                                httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                            });
                    });

        }
        if (ModeAuth == ModeAuthentication.AuthenticationWindows)
        {
            authenticationBuilder.AddNegotiate();
        }

        var app = builder.Build();

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

        app.MapGet("/Frontend", (HttpContext context) =>
        {
            var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
            return $"Frontend {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
        });

        return app;
    }

    private static WebApplication ServerBackend(string[] args, string appsettingsFolder, string appsettingsPath)
    {
        var appsettingsFullname = System.IO.Path.Combine(appsettingsFolder, appsettingsPath);

        var builder = WebApplication.CreateBuilder(args);


        builder.Configuration.AddJsonFile(appsettingsFullname, false, true);

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

        var authenticationBuilder = builder.Services.AddAuthentication();

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport();

        if (ModeAuth == ModeAuthentication.AuthenticationAnonymous)
        {
        }

        if (ModeAuth == ModeAuthentication.AuthenticationCertificate)
        {
            reverseProxyBuilder
                .AddTunnelTransportAuthenticationCertificate();
        }

        if (ModeAuth == ModeAuthentication.AuthenticationWindows)
        {
            authenticationBuilder.AddNegotiate();
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

        builder.Services.AddControllers()
            .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

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
                var socketsHttpHandler = new SocketsHttpHandler();
                if (ModeAuth == ModeAuthentication.AuthenticationWindows)
                {
                    socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
                }
                socketsHttpHandler.ConnectTimeout = TimeSpan.FromSeconds(2);
                socketsHttpHandler.AllowAutoRedirect = false;
                socketsHttpHandler.EnableMultipleHttp2Connections = true;

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
                var socketsHttpHandler = new SocketsHttpHandler();
                if (ModeAuth == ModeAuthentication.AuthenticationWindows)
                {
                    socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
                }
                socketsHttpHandler.ConnectTimeout = TimeSpan.FromSeconds(2);
                socketsHttpHandler.AllowAutoRedirect = false;
                socketsHttpHandler.EnableMultipleHttp2Connections = true;

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
                var socketsHttpHandler = new SocketsHttpHandler();
                if (ModeAuth == ModeAuthentication.AuthenticationWindows)
                {
                    socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
                }
                socketsHttpHandler.ConnectTimeout = TimeSpan.FromSeconds(2);
                socketsHttpHandler.AllowAutoRedirect = false;
                socketsHttpHandler.EnableMultipleHttp2Connections = true;

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
                var socketsHttpHandler = new SocketsHttpHandler();
                if (ModeAuth == ModeAuthentication.AuthenticationWindows)
                {
                    socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
                }
                //socketsHttpHandler.ConnectTimeout = TimeSpan.FromSeconds(2);
                socketsHttpHandler.AllowAutoRedirect = false;
                socketsHttpHandler.EnableMultipleHttp2Connections = true;

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

        if (ModeAuth == ModeAuthentication.AuthenticationCertificate)
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
                        SocketsHttpHandler socketsHttpHandler = new();
                        socketsHttpHandler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                        (socketsHttpHandler.SslOptions.ClientCertificates ??= []).Add(certificate);
                        socketsHttpHandler.SslOptions.LocalCertificateSelectionCallback
                            = (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => certificate;
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
                        SocketsHttpHandler socketsHttpHandler = new();
                        socketsHttpHandler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                        (socketsHttpHandler.SslOptions.ClientCertificates ??= []).Add(certificate);
                        socketsHttpHandler.SslOptions.LocalCertificateSelectionCallback
                            = (sender, targetHost, localCertificates, remoteCertificate, acceptableIssuers) => certificate;
                        socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback
                            = (sender, targetHost, localCertificates, remoteCertificate) => true;
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



        System.Console.WriteLine(System.DateTime.Now.ToString("s"));

        // little bit of speed meassurment
        if (false)
        {
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
                                var socketsHttpHandler = new SocketsHttpHandler();
                                if (ModeAuth == ModeAuthentication.AuthenticationWindows)
                                {
                                    socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
                                }

                                var client = new HttpClient(socketsHttpHandler);
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
    }
}

internal enum ModeAppSettings
{
    H2Anonymous,
    H2Certificate,
    H2WSAnonymous,
    H2WSWindows
}

internal enum ModeAuthentication
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

/*
 
        if (Mode == ModeAuthentication.AuthenticationAnonymous)
        {
        }

        if (Mode == ModeAuthentication.AuthenticationCertificate)
        {
        }

        if (Mode == ModeAuthentication.AuthenticationWindows)
        {
        }


 */
