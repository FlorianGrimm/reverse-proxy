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
        await Task.Delay(1000);

        var builder = Host.CreateApplicationBuilder(args);
        builder.Logging.AddConsole();
        builder.Services.AddOptions<ProgramOptions>()
            .Bind(builder.Configuration.GetRequiredSection(nameof(Program)));
        builder.Services.AddHostedService<Program>();
        var app = builder.Build();
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
            using var clientAPI = GetHttpClient(_options.UrlAPI);
            await TestUntilStarted(clientAPI, stoppingToken);

            using var clientBackend = GetHttpClient(_options.UrlFrontend);
            await TestUntilStarted(clientBackend, stoppingToken);

            using var clientFrontend = GetHttpClient(_options.UrlBackend);
            await TestUntilStarted(clientFrontend, stoppingToken);

            HttpClient[] clients = [clientAPI, clientBackend, clientFrontend];

            var limit = System.DateTime.UtcNow.AddSeconds(10);
            var log = true;
            var loop = 0;
            while (System.DateTime.UtcNow < limit)
            {
                loop++;

                foreach (var test in _options.Tests)
                {
                    if (test.UrlPath.StartsWith("/"))
                    {
                        foreach (var client in clients)
                        {
                            var content = await GetAsync(client, test.UrlPath, log, stoppingToken);
                            TestContent(new Uri(client.BaseAddress!, test.UrlPath), test.Content, content, log);
                        }
                    }
                    else
                    {
                        var uri = new Uri(test.UrlPath);
                        using var client = GetHttpClient(uri.GetLeftPart(UriPartial.Authority));
                        var content = await GetAsync(client, uri.PathAndQuery, log, stoppingToken);
                        TestContent(uri, test.Content, content, log);
                    }
                }
                log = false;
            }
            _logger.LogInformation("Loops {loop}", loop);
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed");
            return;
        }

        _logger.LogInformation("Success");
        /*
        await Task.Delay(2000);
        _serviceProvider.GetRequiredService<IHostApplicationLifetime>().StopApplication();
        */
    }

    private async Task TestUntilStarted(HttpClient client, CancellationToken stoppingToken)
    {
        _logger.LogInformation("First request {client}/", client.BaseAddress?.ToString());
        var limit = System.DateTime.UtcNow.AddSeconds(30);
        while (System.DateTime.UtcNow < limit)
        {
            try
            {
                await GetAsync(client, "/", false, stoppingToken);
                return;
            }
            catch (System.Exception error)
            {
                _logger.LogInformation("Retry since failed: {Message}", error.Message);
                continue;
            }
        }
        _logger.LogInformation("No success {client}/", client.BaseAddress?.ToString());
    }

    private void TestContent(
        Uri urlRequest,
        string expectedContent,
        string actualContent,
        bool log)
    {
        if (actualContent.Contains(expectedContent))
        {
            if (log)
            {
                _logger.LogInformation("OK");
            }
            return;
        }
        _logger.LogWarning("Failed {UrlRequest} {expectedContent}", urlRequest.ToString(), expectedContent);
        throw new Exception("Failed");
    }

    public async Task<string> GetAsync(HttpClient client, string path, bool log, CancellationToken stoppingToken)
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

    public HttpClient GetHttpClient(string url)
    {
        var client = new HttpClient();
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
    public string UrlPath { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;

}
