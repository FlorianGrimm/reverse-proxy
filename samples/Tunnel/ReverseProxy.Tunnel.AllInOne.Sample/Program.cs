// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Tunnel;


try
{
    /*
        The perfomance depend on the console logger (and the logging settings on the appsettings).
        You get better results if you are redirect the output to a file.

        ".\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0\ReverseProxy.Tunnel.AllInOne.Sample.exe" >log.txt

     */
    System.Console.Out.WriteLine("Starting Servers");
    System.Threading.Thread.CurrentThread.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo(1033);
    System.Threading.Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(1033);

    // TODO: remove this after with the configuration works
    var testCertPfxPath = Path.Combine(
        Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!,
        "testCert.pfx");
    var certificate = new X509Certificate2(testCertPfxPath, "testPassword", X509KeyStorageFlags.PersistKeySet);

    List<WebApplication> listWebApplication = [
        ServerFrontend(args, "appsettings.server1FE.json", certificate),
        ServerFrontend(args, "appsettings.server2FE.json", certificate),
        ServerBackend(args, "appsettings.server3BE.json", certificate),
        ServerBackend(args, "appsettings.server4BE.json", certificate),
        ServerAPI(args, "appsettings.server5API.json", certificate),
        ServerAPI(args, "appsettings.server6API.json", certificate)
        ];
    var listTaskRun = listWebApplication.Select(app => app.RunAsync()).ToList();
    var taskRun = Task.WhenAll(listTaskRun);

    System.Console.Out.WriteLine("Starting Tests.");
    // await RunTests();
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

    System.Console.Out.WriteLine("Hit CTRL-C to exit.");
    await taskRun;
}
catch (Exception ex)
{
    System.Console.Error.WriteLine(ex.ToString());
}


static WebApplication ServerFrontend(string[] args, string appsettingsPath, X509Certificate2 certificate)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Configuration.AddJsonFile(appsettingsPath, false, true);
    builder.Services.AddControllers()
        .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);
    builder.WebHost.UseKestrel((context, kestrelOptions) =>
    {
        kestrelOptions.ConfigureHttpsDefaults((HttpsConnectionAdapterOptions httpsOptions) =>
        {
            httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
            httpsOptions.ClientCertificateValidation =
                (X509Certificate2 certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) =>
                {
#warning HELP pretty please I have no experiences with clientcertificates
                    return certificate.Equals(certificate);
                    //return sslPolicyErrors == SslPolicyErrors.None
                    //    || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                };

        });
    });
    builder.Services.AddAuthentication()
        .AddCertificate(options =>
        {
#warning HELP pretty please I have no experiences with clientcertificates
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.RevocationMode = X509RevocationMode.NoCheck;
            options.ValidateCertificateUse = false;
            options.ValidateValidityPeriod = false;

            options.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = context =>
                {
                    if (certificate.Equals(context.ClientCertificate))
                    {
                        context.Success();
                    }
                    // context.NoResult();
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
    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
        .AddTunnelServices()
        ;

    var app = builder.Build();

    app.UseWebSockets();

    app.MapGet("/_CheckCert", async (context) =>
    {
        var cert = await context.Connection.GetClientCertificateAsync();
        if (cert is null)
        {
            await context.Response.WriteAsync("Hello no cert!");
        }
        else
        {
            await context.Response.WriteAsync("Hello cret!");
        }

    }).RequireAuthorization("RequireCertificate");

    app.MapControllers();
    app.MapReverseProxy(
        configureTunnelHTTP2: (endpoint) => endpoint.RequireAuthorization("RequireCertificate"),
        configureTunnelWebSocket: (endpoint) => endpoint.RequireAuthorization("RequireCertificate")
        );
    app.MapGet("/Frontend", (HttpContext context) =>
    {
        var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
        return $"Frontend {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
    });

    return app;
}

static WebApplication ServerBackend(string[] args, string appsettingsPath, X509Certificate2 certificate)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Configuration.AddJsonFile(appsettingsPath, false, true);
    builder.Services.AddControllers()
        .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
        //.AddTunnelServices()
        .UseTunnelTransport(
            configureTunnelHttp2: (options) =>
            {
                options.ConfigureSocketsHttpHandlerAsync = (tunelConfig, socketsHttpHandler) =>
                {
#warning HELP pretty please I have no experiences with clientcertificates
                    var clientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= new();
                    clientCertificates.Add(certificate);
                    return ValueTask.CompletedTask;
                };
            },
            configureTunnelWebSocket: (options) =>
            {
                options.ConfigureClientWebSocket = (tunelConfig, webSocketOptions) =>
                {
#warning HELP pretty please I have no experiences with clientcertificates
                    var clientCertificates = webSocketOptions.Options.ClientCertificates ??= new();
                    clientCertificates.Add(certificate);
                };
            });

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

static WebApplication ServerAPI(string[] args, string appsettingsPath, X509Certificate2 certificate)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Configuration.AddJsonFile(appsettingsPath, false, true);
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

static async Task RunTests()
{
    try
    {
        // to test the certificate
        // https://localhost:5001/_CheckCert
        {
            var testCertPfxPath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!, "testCert.pfx");
            var cert = new X509Certificate2(testCertPfxPath, "testPassword", X509KeyStorageFlags.PersistKeySet);
            SocketsHttpHandler socketsHttpHandler = new();
            socketsHttpHandler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            (socketsHttpHandler.SslOptions.ClientCertificates ??= new()).Add(cert);
            socketsHttpHandler.SslOptions.LocalCertificateSelectionCallback
                = (object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate? remoteCertificate, string[] acceptableIssuers) => cert;
            HttpClient httpClient = new(socketsHttpHandler);
            var url = "https://localhost:5001/_CheckCert";
            System.Console.Out.WriteLine($"Sending request to {url}");
            var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadAsStringAsync();
            System.Console.Out.WriteLine($"Success: {result}");
        }

        // https://localhost:5001/test
        {
            using HttpClient httpClient = new();
            var url = "https://localhost:5001/test";
            System.Console.Out.WriteLine($"Sending request to {url}");
            using var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
            response.EnsureSuccessStatusCode();
            var result = await response.Content.ReadAsStringAsync();
            if (result.Contains(" \"host\": \"localhost:5005\",") || result.Contains(" \"host\": \"localhost:5006\","))
            {
                System.Console.Out.WriteLine($"Success: {result}");
            }
            else
            {
                System.Console.Out.WriteLine($"Failed: {result}");
            }
        }

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
            var cntloop = 1;
            for (var loop = 1; loop <= cntloop; loop++)
            {
                System.Console.Out.WriteLine($"{loop} / {cntloop}");

                for (var index = 0; index < listTestSettings.Length; index++)
                {
                    var testSettings = listTestSettings[index];
                    var sw = Stopwatch.StartNew();
                    List<(HttpClient httpClient, Task<string> taskGetString)> listTask = new();

                    for (var innerloop = 0; innerloop < 20; innerloop++)
                    {
                        var client = new HttpClient(new SocketsHttpHandler());
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

                System.Console.WriteLine($"{testSettings.Url} - {minDuration} / {averageDuration} / {maxDuration}");
                foreach (var (content, count) in testSettings.Count.ToList().OrderBy(c => c.Key))
                {
                    System.Console.WriteLine($"{count} - {content}");
                }

            }
        }
    }
    catch (Exception error)
    {
        System.Console.Error.WriteLine(error.ToString());
        if (error.InnerException is not null)
        {
            System.Console.Error.WriteLine(error.InnerException.ToString());
        }
    }
}

internal record TestSettings(string Url)
{
    public readonly ConcurrentDictionary<string, int> Count = new();
    public readonly List<long> Duration = new List<long>(1000);
}
