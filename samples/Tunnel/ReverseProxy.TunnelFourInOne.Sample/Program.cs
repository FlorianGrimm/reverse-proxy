using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
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
}
