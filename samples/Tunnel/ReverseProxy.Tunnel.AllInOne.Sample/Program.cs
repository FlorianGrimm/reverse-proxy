// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
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
    List<WebApplication> listWebApplication = [
        ServerA1(args),
        ServerB1(args)
        ];
    var listTaskRun = listWebApplication.Select(app => app.RunAsync()).ToList();
    var taskRun = Task.WhenAll(listTaskRun);
    System.Console.Out.WriteLine("Servers Started.");

    await Tests();

    await taskRun;
}
catch (Exception ex)
{
    System.Console.Error.WriteLine(ex.ToString());
}

static WebApplication ServerA1(string[] args)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        { "Urls", "https://localhost:5001" }
    });
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
                    return true;
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
            var testCertPfxPath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!, "testCert.pfx");
            using var certificate = new X509Certificate2(testCertPfxPath, "testPassword", X509KeyStorageFlags.PersistKeySet);
            var serialNumber = certificate.GetSerialNumber();

            options.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = context =>
                {
                    var isEqual = serialNumber.SequenceEqual(context.ClientCertificate.GetSerialNumber());
                    if (isEqual)
                    {
                        context.Success();
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
    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxyA1"));

    builder.Services.AddTunnelServices();

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
    app.MapReverseProxy();

    // Uncomment to support websocket connections
    // app.MapWebSocketTunnel("/connect-ws");

    // Auth can be added to this endpoint and we can restrict it to certain points
    // to avoid exteranl traffic hitting it
    app.MapHttp2Tunnel("/connect-h2"); //.RequireAuthorization("RequireCertificate");

    return app;
}

static WebApplication ServerB1(string[] args)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        { "Urls", "https://localhost:5003" }
    });
    builder.Services.AddControllers()
        .AddJsonOptions(options => options.JsonSerializerOptions.WriteIndented = true);

    builder.Services.AddReverseProxy()
        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxyB1"));

    // This is the HTTP/2 endpoint to register this app as part of the cluster endpoint
    var url = builder.Configuration["TunnelB1:Url"]!;

    var testCertPfxPath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)!, "testCert.pfx");
    var cert = new X509Certificate2(testCertPfxPath, "testPassword", X509KeyStorageFlags.PersistKeySet);

    builder.WebHost.UseTunnelTransportHttp2(new Uri(url), options => {
        options.ConfigureSocketsHttpHandler = (uri, handler) =>
        {
            handler.SslOptions.AddClientCertificate(cert);
        };
    });

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
            HttpClient httpClient = new();
            var url = "https://localhost:5001/test";
            System.Console.Out.WriteLine($"Sending request to {url}");
            var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
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

        // call https://localhost:5001/test 100 time in parralell
        {
            int countSuccess = 0;
            int countFail = 0;
            var tasks = System.Linq.Enumerable.Range(0, 100).AsParallel().Select(async i =>
            {
                HttpClient httpClient = new();
                var url = "https://localhost:5001/test";
                System.Console.Out.WriteLine($"Sending request to {url}");
                var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Get, url));
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
            });
            await Task.WhenAll(tasks.ToArray());

            System.Console.Out.WriteLine($"Success: {countSuccess} Failes: {countFail}");
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
