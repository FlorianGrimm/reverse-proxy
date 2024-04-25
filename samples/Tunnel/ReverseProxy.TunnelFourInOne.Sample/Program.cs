using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace SampleTunnelFourInOne;

public class Program
{
    public static async Task Main()
    {
        try
        {
            ServerBase[] servers = [
                new Server1FE(),
                new Server2FE(),
                new Server3T(),
                new Server4T(),
                new Server5Api(),
                new Server6Api()
            ];

            var tasks = new Task[servers.Length];

            for (var idx = 0; idx < servers.Length; idx++)
            {
                var server = servers[idx];
                tasks[idx] = server.RunAsync();
                server.Lifetime.ApplicationStopping.Register(stop);
            }

#if false
            await RunTests();
            await RunMoreTests();
            stop();
#endif

            await Task.WhenAll(tasks);

            void stop()
            {
                for (var idx = 0; idx < servers.Length; idx++)
                {
                    var server = servers[idx];
                    server.Lifetime.StopApplication();
                }
            }
        }
        catch (System.AggregateException error)
        {
            error.Handle((e) =>
            {
                System.Console.Error.WriteLine(e.ToString());
                return true;
            });
            throw;
        }
        catch (System.Exception error)
        {
            System.Console.Error.WriteLine(error.ToString());
            throw;
        }

    }

    private static async Task RunTests()
    {
        try
        {
            // Backend
            await HttpClientGet("https://localhost:5005");
            await HttpClientGet("https://localhost:5006");

            // normal Yarp forwarding
            await HttpClientGet("https://localhost:5004/alpha");
            await HttpClientGet("https://localhost:5004/beta");
            await HttpClientGet("https://localhost:5004/gamma");
            await HttpClientGet("https://localhost:5004");

            await HttpClientGet("https://localhost:5003/alpha");
            await HttpClientGet("https://localhost:5003/beta");
            await HttpClientGet("https://localhost:5003/gamma");
            await HttpClientGet("https://localhost:5003");


            // Tunnel

            await HttpClientGet("https://localhost:5002/alpha");
            await HttpClientGet("https://localhost:5002/beta");
            await HttpClientGet("https://localhost:5002/gamma");
            await HttpClientGet("https://localhost:5002");


            await HttpClientGet("https://localhost:5001/alpha");
            await HttpClientGet("https://localhost:5001/beta");
            await HttpClientGet("https://localhost:5001/gamma");
            await HttpClientGet("https://localhost:5001");
        }
        catch (Exception error)
        {
            System.Console.Error.WriteLine(error.ToString());
        }
    }


    private static async Task RunMoreTests()
    {
        try
        {
            var duration56 = await MeassureTests(
                "https://localhost:5006/alpha",
                "https://localhost:5006/beta",
                "https://localhost:5005/alpha",
                "https://localhost:5005/beta"
                );
            var duration43 = await MeassureTests(
                "https://localhost:5004/alpha",
                "https://localhost:5004/beta",
                "https://localhost:5004/gamma",
                "https://localhost:5004",
                "https://localhost:5003/alpha",
                "https://localhost:5003/beta",
                "https://localhost:5003/gamma",
                "https://localhost:5003"
                );

            var duration21 = await MeassureTests(
                "https://localhost:5002/alpha",
                "https://localhost:5002/beta",
                "https://localhost:5002/gamma",
                "https://localhost:5002",
                "https://localhost:5001/alpha",
                "https://localhost:5001/beta",
                "https://localhost:5001/gamma",
                "https://localhost:5001"
                );
            System.Console.Error.WriteLine($"duration56: {(duration56).TotalMilliseconds}");
            System.Console.Error.WriteLine($"duration43: {(duration43).TotalMilliseconds}");
            System.Console.Error.WriteLine($"duration21: {(duration21).TotalMilliseconds}");
        }
        catch (Exception error)
        {
            System.Console.Error.WriteLine(error.ToString());
        }
    }

    private static async Task<TimeSpan> MeassureTests(params string[] urls)
    {
        var lst = System.Linq.Enumerable.Range(0, 100).ToList();
        var start = System.DateTimeOffset.UtcNow;
        List<Task> tasks = new();
        foreach (var url in urls)
        {
            for (var idx = 0; idx < 100; idx++) {
                var task= Task.Run(async () => {
                    for (var idx = 0; idx < 10; idx++)
                    {
                        await HttpClientGet(url, false);
                    }
                });
                tasks.Add(task);
            }
        }
        await Task.WhenAll(tasks);
        var stop = System.DateTimeOffset.UtcNow;
        var duration = (stop - start);
        System.Console.Error.WriteLine(duration.TotalMilliseconds.ToString());
        return duration;
    }

    private static readonly ConcurrentDictionary<string, HttpClient> _cache = new();

    private static async Task<(HttpStatusCode, string)> HttpClientGet(string url, bool withOutput = true)
    {
        if (withOutput)
        {
            System.Console.Out.WriteLine("");
            System.Console.Out.WriteLine("---------------------------------------");
            System.Console.Out.WriteLine("");
            System.Console.Out.WriteLine($"GET {url}");
        }
        var key = (new Uri(url)).GetLeftPart(UriPartial.Authority);
        if (!_cache.TryGetValue(key, out var httpClient))
        {
            httpClient = new HttpClient();
            _cache.TryAdd(key, httpClient);
        }
        using var response = await httpClient.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();
        var statusCode = response.StatusCode;
        if (withOutput)
        {
            var displayContent = string.IsNullOrEmpty(content) ? "--EMPTY--" : content.Length < 42 ? content : content.Substring(0, 42);
            System.Console.Out.WriteLine($"{statusCode} {content}");
        }
        return (statusCode, content);
    }
}
