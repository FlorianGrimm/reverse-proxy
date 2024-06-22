// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Tunnel;


try
{
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
    System.Console.Out.WriteLine("Servers Started.");

    System.Console.Out.WriteLine("Starting Tests.");
    await RunTests();
    /*
        https://localhost:5001/Frontend - 181,0748 / 247,8223 / 314,5699
        40 - Frontend https://localhost:5001/ - localhost:5001 - ::1:5001
        https://localhost:5002/Frontend - 160,4714 / 181,975 / 203,4786
        40 - Frontend https://localhost:5002/ - localhost:5002 - ::1:5002
        https://localhost:5001/Backend - 519,7178 / 611,0843 / 702,4509
        20 - Backend https://localhost:5003/ - alpha - :0
        20 - Backend https://localhost:5004/ - alpha - :0
        https://localhost:5002/Backend - 538,9789 / 547,916 / 556,8532
        20 - Backend https://localhost:5003/ - alpha - :0
        20 - Backend https://localhost:5004/ - alpha - :0
        https://localhost:5001/API - 743,405 / 833,0081 / 922,6112
        40 - API https://localhost:5005/ - localhost:5005 - ::1:5005
        https://localhost:5002/API - 739,6996 / 1008,1259 / 1276,5522
        40 - API https://localhost:5005/ - localhost:5005 - ::1:5005
        https://localhost:5001/alpha/API - 714,1733 / 892,9486 / 1071,7239
        40 - API https://localhost:5005/ - localhost:5005 - ::1:5005
        https://localhost:5002/beta/API - 780,9526 / 928,0831 / 1075,2136
        40 - API https://localhost:5006/ - localhost:5006 - ::1:5006
     */

    System.Console.Out.WriteLine("Done Tests.");
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
                    return certificate.Equals(certificate);
                    //return sslPolicyErrors == SslPolicyErrors.None
                    //    || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
                };

        });
    });
    builder.Services.AddAuthentication()
        .AddCertificate(options =>
        {
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
    app.MapGet("/Frontend", (HttpContext context) => {
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
            builder,
            configureTunnelHttp2: (options) =>
            {
                options.ConfigureSocketsHttpHandlerAsync = (tunelConfig, socketsHttpHandler) =>
                {
                    var clientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= new();
                    clientCertificates.Add(certificate);
                    return ValueTask.CompletedTask;
                };
            },
            configureTunnelWebSocket: (options) => {
                options.ConfigureClientWebSocket = (tunelConfig, webSocketOptions) =>
                {
                    var clientCertificates = webSocketOptions.Options.ClientCertificates ??= new();
                    clientCertificates.Add(certificate);
                };
            });

    var app = builder.Build();

    app.UseWebSockets();
    app.MapControllers();
    app.MapReverseProxy();
    app.MapGet("/Backend", (HttpContext context) => {
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
    app.MapGet("/API", (HttpContext context) => {
        var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
        return $"API {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
    });
    app.MapGet("/alpha/API", (HttpContext context) => {
        var urls = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("Urls");
        return $"API {urls} - {context.Request.Host} - {context.Connection.LocalIpAddress}:{context.Connection.LocalPort}";
    });
    app.MapGet("/beta/API", (HttpContext context) => {
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
            var cntloop = 2;
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
                foreach (var (content, count) in testSettings.Count.ToList().OrderBy(c => c.Key)) {
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

internal record TestSettings (string Url){
    public readonly ConcurrentDictionary<string, int> Count=new();
    public readonly List<long> Duration = new List<long>(1000);
}
