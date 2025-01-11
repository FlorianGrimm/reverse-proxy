#pragma warning disable CA1866 // Use char overload

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ReverseProxy.Tunnel.Basic.Client;

public class Program : BackgroundService
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Configuration.AddJsonFile(System.IO.Path.Combine(System.AppContext.BaseDirectory, "appsettings.json"), false);
        builder.Logging.AddConsole();

        builder.Services.AddOptions<ProgramOptions>()
            .Bind(builder.Configuration.GetRequiredSection(nameof(Program)));
        builder.Services.AddHostedService<Program>();
        var app = builder.Build();
        await Task.Delay(1000);
        await app.RunAsync();
    }

    private readonly ProgramOptions _options;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<Program> _logger;

    public Program(
        IOptions<ProgramOptions> options,
        IServiceProvider serviceProvider,
        ILogger<Program> logger
        )
    {
        _options = options.Value;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var clientAPIUnauthenticated = GetHttpClient(_options.UrlAPI, false);
            using var clientBackendUnauthenticated = GetHttpClient(_options.UrlFrontend, false);
            using var clientFrontendUnauthenticated = GetHttpClient(_options.UrlBackend, false);

            using var clientAPIAuthenticated = GetHttpClient(_options.UrlAPI, true);
            using var clientBackendAuthenticated = GetHttpClient(_options.UrlFrontend, true);
            using var clientFrontendAuthenticated = GetHttpClient(_options.UrlBackend, true);

            await TestUntilStarted(clientAPIAuthenticated, stoppingToken);
            await TestUntilStarted(clientBackendAuthenticated, stoppingToken);
            await TestUntilStarted(clientFrontendAuthenticated, stoppingToken);

            HttpClient[] clientsUnauthenticated = [clientAPIUnauthenticated, clientBackendUnauthenticated, clientFrontendUnauthenticated];
            HttpClient[] clientsAuthenticated = [clientAPIAuthenticated, clientBackendAuthenticated, clientFrontendAuthenticated];
            var clientsUnauthenticatedByBaseAddress = clientsUnauthenticated.ToDictionary(client => client.BaseAddress!.GetLeftPart(UriPartial.Authority));
            var clientsAuthenticatedByBaseAddress = clientsAuthenticated.ToDictionary(client => client.BaseAddress!.GetLeftPart(UriPartial.Authority));

            var limit = System.DateTime.UtcNow.AddSeconds(10);
            var log = true;
            var loop = 0;
            while (System.DateTime.UtcNow < limit)
            {
                loop++;

                for (var index = 0; index < _options.Tests.Count; index++)
                {
                    var test = _options.Tests[index];
                    // _logger.LogInformation("test.UrlPath:{UrlPath}", test.UrlPath);
                    if (test.UrlPath.StartsWith("/"))
                    {
                        var clients = test.Authenticate ? clientsAuthenticated : clientsUnauthenticated;
                        foreach (var client in clients)
                        {
                            var content = await GetContentAsync(client, test.UrlPath, log, stoppingToken);
                            TestContent(index, new Uri(client.BaseAddress!, test.UrlPath), test.Content, content, log);
                        }
                    }
                    else
                    {
                        var uri = new Uri(test.UrlPath);
                        var dictClients = test.Authenticate ? clientsAuthenticatedByBaseAddress : clientsUnauthenticatedByBaseAddress;
                        var uriAuthority = uri.GetLeftPart(UriPartial.Authority);
                        if (dictClients.TryGetValue(uriAuthority.ToString(), out var existingClient))
                        {
                            var content = await GetContentAsync(existingClient, test.UrlPath, log, stoppingToken);
                            TestContent(index, uri, test.Content, content, log);
                        }
                        else
                        {
                            using var extraClient = GetHttpClient(uri.GetLeftPart(UriPartial.Authority), test.Authenticate);
                            var content = await GetContentAsync(extraClient, test.UrlPath, log, stoppingToken);
                            TestContent(index, uri, test.Content, content, log);
                        }
                    }
                }
                log = false;
            }
            _logger.LogInformation("Loops {loop}", loop);
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed");
            _serviceProvider.GetRequiredService<IHostApplicationLifetime>().StopApplication();
            return;
        }

        _logger.LogInformation("Success");
        /*
            await Task.Delay(2000);
            */
            _serviceProvider.GetRequiredService<IHostApplicationLifetime>().StopApplication();
    }

    private async Task TestUntilStarted(HttpClient client, CancellationToken stoppingToken)
    {
        _logger.LogInformation("First request {client}/", client.BaseAddress?.ToString());
        var limit = System.DateTime.UtcNow.AddSeconds(30);
        while (System.DateTime.UtcNow < limit)
        {
            try
            {
                await GetContentAsync(client, "/", false, stoppingToken);
                return;
            }
            catch (System.Exception error)
            {
                _logger.LogInformation("First request {client} Retry since failed: {Message}", client.BaseAddress?.ToString(), error.Message);
                continue;
            }
        }
        _logger.LogInformation("No success {client}/", client.BaseAddress?.ToString());
    }

    private void TestContent(
        int index,
        Uri urlRequest,
        string expectedContent,
        string actualContent,
        bool log)
    {
        if (actualContent.Contains(expectedContent))
        {
            if (log)
            {
                _logger.LogInformation("{index} - OK", index);
            }
            return;
        }
        _logger.LogWarning("{index} Failed {UrlRequest} {expectedContent}", index, urlRequest.ToString(), expectedContent);
        throw new Exception("Failed");
    }

    public async Task<string> GetContentAsync(HttpClient client, string path, bool log, CancellationToken stoppingToken)
    {
        if (log)
        {
            _logger.LogInformation("Request GET {client} {path}", client.BaseAddress?.ToString(), path);
        }
        using (var response = await client.GetAsync(path, stoppingToken))
        {
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            return content;
        }
    }

    public HttpClient GetHttpClient(string url, bool authenticated)
    {
        var httpClientHandler = new HttpClientHandler();
        if (authenticated)
        {
            httpClientHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
        }
        var client = new HttpClient(httpClientHandler);
        client.BaseAddress = new Uri(url);
        return client;
    }

}

public class ProgramOptions
{
    public string UrlFrontend { get; set; } = string.Empty;

    public string UrlBackend { get; set; } = string.Empty;

    public string UrlAPI { get; set; } = string.Empty;

    public List<TestOptions> Tests { get; set; } = new();
}

public class TestOptions
{
    public bool Authenticate { get; set; }
    public string UrlPath { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;

}
