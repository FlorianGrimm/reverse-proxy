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

    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w browser-negotiate test 
    ".\ReverseProxy.Tunnel.AllInOne.Sample.exe" h2ws-w browser-negotiate test measure stop

    h2-a|h2-c|h2-w|h2ws-a|h2ws-w|ws-a|ws-c|ws-w]
    browser-negotiate
    browser-oauth
#endif

internal partial class Program
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
            System.Console.Out.WriteLine("Syntax: [h2-anonymous|h2-certificate|h2-jwtbaerer|h2-negotiate|h2ws-anonymous|h2ws-negotiate|ws-anonymous|ws-certificate|ws-negotiate] [browser-anonymous|browser-negotiate|browser-oauth] [none][1][2][3][4][5][6] [test] [measure] [stop]");
            System.Console.Out.WriteLine("Tunnel protocol-authentication");
            System.Console.Out.WriteLine("  h2-: HTTP/2");
            System.Console.Out.WriteLine("  ws-: WebSocket");
            System.Console.Out.WriteLine("  -anonymous: Anonymous");
            System.Console.Out.WriteLine("  -certificate: Client Certificate authentication");
            System.Console.Out.WriteLine("  -negotiate: Windows authentication");
            System.Console.Out.WriteLine("  -jwtbaerer: JwtBaerer");
            System.Console.Out.WriteLine("Browser Authentication:");
            System.Console.Out.WriteLine("browser-anonymous: browser wants no auth");
            System.Console.Out.WriteLine("browser-negotiate: browser wants windows auth");
            System.Console.Out.WriteLine("[1][2][3][4][5][6] which server to start none specified means all");
            System.Console.Out.WriteLine("test:     do some tests");
            System.Console.Out.WriteLine("measure: do some request and measure the time");
            System.Console.Out.WriteLine("stop:     after test and/or measure stop and don't wait for CTRL-C.");
        }

        var hsArgs = args.ToHashSet();
        var appsettingsFolder = ParseArgs(hsArgs);
        var (sNone, s1, s2, s3, s4, s5, s6) = (hsArgs.Remove("none"), hsArgs.Remove("1"), hsArgs.Remove("2"), hsArgs.Remove("3"), hsArgs.Remove("4"), hsArgs.Remove("5"), hsArgs.Remove("6"));
        var (test, measure, wait) = (hsArgs.Remove("test"), hsArgs.Remove("measure"), !hsArgs.Remove("stop") || hsArgs.Remove("wait"));

        if (0 < hsArgs.Count)
        {
            System.Console.WriteLine($"Unknown args {string.Join(" ", hsArgs)}");
            return 1;
        }

        List<WebApplication> listWebApplication = [];
        try
        {
            Console.Out.WriteLine("Starting Servers");
            Thread.CurrentThread.CurrentUICulture = System.Globalization.CultureInfo.GetCultureInfo(1033);
            Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.GetCultureInfo(1033);

            Task taskRunServer;
            {
                var allServers = sNone ? false : (!s1 && !s2 && !s3 && !s4 && !s5 && !s6);

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
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
        finally
        {
            foreach (var app in listWebApplication)
            {
                await app.Services.GetRequiredService<Brimborium.Extensions.Logging.LocalFile.LocalFileLoggerProvider>().FlushAsync(CancellationToken.None);
            }
        }
        return 0;
    }

    private static string ParseArgs(HashSet<string> hsArgs)
    {
        // tunnel 
        {
            var (
                h2_anonymous, h2_certificate, h2_negotiate, h2_jwtbaerer,
                h2ws_anonymous, h2ws_negotiate,
                ws_anonymous, ws_certificate, ws_negotiate) = (
                hsArgs.Remove("h2-anonymous"), hsArgs.Remove("h2-certificate"), hsArgs.Remove("h2-negotiate"), hsArgs.Remove("h2-jwtbaerer"),
                hsArgs.Remove("h2ws-anonymous"), hsArgs.Remove("h2ws-negotiate"),
                hsArgs.Remove("ws-anonymous"), hsArgs.Remove("ws-certificate"), hsArgs.Remove("ws-negotiate"));

            if (h2_anonymous) { _modeAppSettings = ModeAppSettings.H2Anonymous; }
            else if (h2_certificate) { _modeAppSettings = ModeAppSettings.H2Certificate; }
            else if (h2_negotiate) { _modeAppSettings = ModeAppSettings.H2Negotiate; }
            else if (h2_jwtbaerer) { _modeAppSettings = ModeAppSettings.H2JwtBaerer; }

            else if (h2ws_anonymous) { _modeAppSettings = ModeAppSettings.H2WSAnonymous; }
            else if (h2ws_negotiate) { _modeAppSettings = ModeAppSettings.H2WSNegotiate; }

            else if (ws_anonymous) { _modeAppSettings = ModeAppSettings.WSAnonymous; }
            else if (ws_certificate) { _modeAppSettings = ModeAppSettings.WSCertificate; }
            else if (ws_negotiate) { _modeAppSettings = ModeAppSettings.WSNegotiate; }

            else {
                throw new InvalidOperationException("no valid mode");
            }
        }

        // browser authentication
        {
            var browserWindows = hsArgs.Remove("browser-negotiate");
            var browserAnonymous = hsArgs.Remove("browser-anonymous");

            if (browserWindows)
            {
                _browserAuthentication = BrowserAuthentication.Negotiate;
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
            else if (_modeAppSettings == ModeAppSettings.H2Negotiate)
            {
                appsettingsFolder = "appsettings-H2-Negotiate";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationNegotiate;
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
            else if (_modeAppSettings == ModeAppSettings.H2WSNegotiate)
            {
                appsettingsFolder = "appsettings-H2WS-Negotiate";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationNegotiate;
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
            else if (_modeAppSettings == ModeAppSettings.WSNegotiate)
            {
                appsettingsFolder = "appsettings-WS-Negotiate";
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationNegotiate;
                enableTunnelWS = true;
            }
            else
            {
                throw new InvalidOperationException("modeAppSettings is unsupported.");
            }
        }

        if (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationCertificate)
        {
            if (_browserAuthentication == BrowserAuthentication.Anonymous)
            {
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationCertificateAuthProvider;
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationCertificateRequest;
            }
            else
            {
                _modeTunnelAuthentication = TunnelAuthentication.AuthenticationCertificateRequest;
            }
        }
        appsettingsFolder = System.IO.Path.Combine(System.AppContext.BaseDirectory, appsettingsFolder);
        System.Console.WriteLine(appsettingsFolder);
        return appsettingsFolder;
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
        if (_browserAuthentication == BrowserAuthentication.Negotiate)
        {
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
        if ((_browserAuthentication == BrowserAuthentication.Negotiate)
            || (_modeTunnelAuthentication == TunnelAuthentication.AuthenticationNegotiate))
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
    H2Negotiate,
    H2JwtBaerer,

    H2WSAnonymous,
    H2WSNegotiate,

    WSAnonymous,
    WSCertificate,
    WSNegotiate
}

internal enum BrowserAuthentication
{
    Anonymous,
    Negotiate
}

internal enum TunnelAuthentication
{
    AuthenticationAnonymous,
    AuthenticationCertificate,
    AuthenticationCertificateAuthProvider,
    AuthenticationCertificateRequest,
    AuthenticationNegotiate,
    AuthenticationJwtBearer
}


internal record TestSettings(string Url)
{
    public readonly ConcurrentDictionary<string, int> Count = new();
    public readonly List<long> Duration = new(1000);
}
