// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
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

    // await Tests();

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

    ;

#warning CERTS
    //builder.WebHost.UseTunnelTransportHttp2(new Uri(url), options =>
    //{
    //    options.ConfigureSocketsHttpHandler = (uri, handler) =>
    //    {
    //        handler.SslOptions.AddClientCertificate(cert);
    //    };
    //});

    var app = builder.Build();

    app.UseWebSockets();
    app.MapControllers();
    app.MapReverseProxy();

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

    return app;
}

static async Task Tests()
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
            if (result.Contains(" \"host\": \"backend1.app\","))
            {
                System.Console.Out.WriteLine($"Success: {result}");
            }
            else
            {
                System.Console.Out.WriteLine($"Failed: {result}");
            }
        }

        // call https://localhost:5001/test 10*10 times
        {
            var startGlobal = Stopwatch.GetTimestamp();
            List<long> listDuration = new(100);
            int countSuccess = 0;
            int countFail = 0;
            var tasks = System.Linq.Enumerable.Range(0, 10).Select(async i =>
            {
                using HttpClient httpClient = new();
                for (int iLoop = 0; iLoop < 10; iLoop++)
                {
                    var startLoop = Stopwatch.GetTimestamp();
                    var url = "https://localhost:5001/test";
                    using var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
                    response.EnsureSuccessStatusCode();
                    var result = await response.Content.ReadAsStringAsync();
                    if (result.Contains(" \"host\": \"backend1.app\","))
                    {
                        System.Threading.Interlocked.Increment(ref countSuccess);
                    }
                    else
                    {
                        System.Threading.Interlocked.Increment(ref countFail);
                    }
                    var duration = Stopwatch.GetTimestamp() - startLoop;
                    lock (listDuration)
                    {
                        listDuration.Add(duration);
                    }
                }
            });
            await Task.WhenAll(tasks.ToArray());
            
            var allTotalMilliseconds = TimeSpan.FromTicks(Stopwatch.GetTimestamp() - startGlobal).TotalMilliseconds;
            var minDuration = TimeSpan.FromTicks(listDuration.Min()).TotalMilliseconds;
            var maxDuration = TimeSpan.FromTicks(listDuration.Max()).TotalMilliseconds;
            var averageDuration = TimeSpan.FromTicks(listDuration.Sum()/listDuration.Count).TotalMilliseconds;
            System.Console.Out.WriteLine($"Success: {countSuccess} Failes: {countFail}");
            System.Console.Out.WriteLine($"min: {minDuration}; avg: {averageDuration}; max: {maxDuration}");
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


/*
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();


app.MapControllers();

app.Run();
*/
