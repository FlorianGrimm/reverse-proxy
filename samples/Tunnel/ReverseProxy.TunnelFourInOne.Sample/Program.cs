using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

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

            // await RunTests();

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
        await Task.Delay(1000);

        try
        {
            // Backend
            await HttpClientGet("https://localhost:5005");
            await HttpClientGet("https://localhost:5006");

            // normal Yarp forwarding
            await HttpClientGet("https://localhost:5004/alpha");
            await HttpClientGet("https://localhost:5004/beta");
            await HttpClientGet("https://localhost:5004/gamma");

            await HttpClientGet("https://localhost:5003/alpha");
            await HttpClientGet("https://localhost:5003/beta");
            await HttpClientGet("https://localhost:5003/gamma");


            // Tunnel

            await HttpClientGet("https://localhost:5002/alpha");
        }
        catch (Exception error)
        {
            System.Console.Error.WriteLine(error.ToString());
        }
    }

    private static async Task<(HttpStatusCode, string)> HttpClientGet(string url)
    {
        System.Console.Out.WriteLine("");
        System.Console.Out.WriteLine("---------------------------------------");
        System.Console.Out.WriteLine("");
        System.Console.Out.WriteLine($"GET {url}");
        using var httpClient = new HttpClient();
        using var response = await httpClient.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();
        var statusCode = response.StatusCode;
        var displayContent = string.IsNullOrEmpty(content) ? "--EMPTY--" : content.Length < 42 ? content : content.Substring(0, 42);
        System.Console.Out.WriteLine($"{statusCode} {content}");
        return (statusCode, content);
    }
}
