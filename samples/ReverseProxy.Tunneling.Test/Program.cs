#pragma warning disable IDE0060 // Remove unused parameter

using System.IO.Pipes;

namespace ReverseProxy.Tunneling.Test;

public class Program
{
    public static async Task Main2(string[] args)
    {
        // https://andrewlock.net/using-named-pipes-with-aspnetcore-and-httpclient/
        // pipe+https://./sample-server/abc
        var url = "pipe+https://localhost/sample-server/abc";
        //url.StartsWith("pipe+")
        var uri = new Uri(url);
        var baseAddress = new Uri(uri.GetLeftPart(UriPartial.Authority).Substring(5));   // 👈 Use localhost as the base address     
        var serverName = string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase) ?  "." : uri.Host ;  // 👈 this machine
        //var pipeName = "sample-server"; // 👈
        var pipeName = uri.Segments[1].TrimEnd('/');
        var urlServerRelative = string.Join("", uri.Segments.Where((_, i) => i != 1))+uri.Query+uri.Fragment;
        var httpHandler = new SocketsHttpHandler
        {
            // Called to open a new connection
            ConnectCallback = async (ctx, ct) =>
            {
                // Configure the named pipe stream
                var pipeClientStream = new NamedPipeClientStream(
                    serverName: serverName,
                    pipeName: pipeName,
                    PipeDirection.InOut, // We want a duplex stream 
                    PipeOptions.Asynchronous); // Always go async

                // Connect to the server!
                await pipeClientStream.ConnectAsync(ct);
                return pipeClientStream;
            }
        };

        // Create an HttpClient using the named pipe handler
        using var client = new HttpClient(httpHandler)
        {
            BaseAddress = baseAddress
        };

        try
        {
            using var response = await client.GetAsync(urlServerRelative);
            response.EnsureSuccessStatusCode();
            var responseBody = await response.Content.ReadAsStringAsync();
            System.Console.Out.WriteLine(responseBody);
        }
        catch (Exception error)
        {
            System.Console.Error.WriteLine(error.ToString());
        }
    }

    public static async Task Main(string[] args)
    {
        var assemblyLocation = System.IO.Path.ChangeExtension(typeof(Program).Assembly.Location, ".exe");

        var frontEndLocation = assemblyLocation.Replace("ReverseProxy.Tunneling.Test", "ReverseProxy.Tunneling.FrontEnd.Sample");
        if (!System.IO.File.Exists(frontEndLocation))
        {
            Console.WriteLine($"frontend not found:{frontEndLocation}");
            return;
        }
        var backEndLocation = assemblyLocation.Replace("ReverseProxy.Tunneling.Test", "ReverseProxy.Tunneling.BackEnd.Sample");
        if (!System.IO.File.Exists(backEndLocation))
        {
            Console.WriteLine($"backend not found:{backEndLocation}");
            return;
        }
        var sampleServerLocation = assemblyLocation.Replace("ReverseProxy.Tunneling.Test", "SampleServer");
        if (!System.IO.File.Exists(sampleServerLocation))
        {
            Console.WriteLine($"sampleServer not found:{sampleServerLocation}");
            return;
        }

        System.Diagnostics.Process? sampleServerProcess = null;
        System.Diagnostics.Process? frontEndProcess = null;
        System.Diagnostics.Process? backEndProcess = null;
        try
        {
            Console.WriteLine($"start sampleServer:{sampleServerLocation}");
            System.Diagnostics.ProcessStartInfo psiSampleServer = new()
            {
                FileName = sampleServerLocation,
                WorkingDirectory = System.IO.Path.GetDirectoryName(sampleServerLocation),
                Arguments = "--Urls \"https://pipe:/sample-server;https://localhost:5001\"",
                UseShellExecute = true,
                CreateNoWindow = false
            };
            /*
             dotnet run --framework net8.0  -- --Urls="https://pipe:/sample-server;https://localhost:5001"
             dotnet run --framework net8.0  -- --Urls="https://pipe:/sample-server"
             */
            sampleServerProcess = System.Diagnostics.Process.Start(psiSampleServer);

            Console.WriteLine($"start frontend:{frontEndLocation}");
            System.Diagnostics.ProcessStartInfo psiFrontEnd = new()
            {
                FileName = frontEndLocation,
                WorkingDirectory = System.IO.Path.GetDirectoryName(frontEndLocation),
                Arguments = """--Urls https://localhost:7244""",
                UseShellExecute = true,
                CreateNoWindow = false
            };

            frontEndProcess = System.Diagnostics.Process.Start(psiFrontEnd);

            Console.WriteLine($"start backEnd:{backEndLocation}");
            System.Diagnostics.ProcessStartInfo psiBackEnd = new()
            {
                FileName = backEndLocation,
                WorkingDirectory = System.IO.Path.GetDirectoryName(backEndLocation),
                Arguments = """--Urls https://localhost:7207""",
                UseShellExecute = true,
                CreateNoWindow = false
            };
            backEndProcess = System.Diagnostics.Process.Start(psiBackEnd);

            await Task.Delay(5000);

            if (sampleServerProcess is null || sampleServerProcess.HasExited
                || frontEndProcess is null || frontEndProcess.HasExited
                || backEndProcess is null || backEndProcess.HasExited
                )
            {
                return;
            }

            System.Console.Out.WriteLine("GET https://localhost:5001");
            {
                using HttpClient client = new()
                {
                    BaseAddress = new Uri("https://localhost:5001")
                };

                try
                {
                    using var response = await client.GetAsync("https://localhost:5001");
                    response.EnsureSuccessStatusCode();
                    var responseBody = await response.Content.ReadAsStringAsync();
                    System.Console.Out.WriteLine(responseBody);
                }
                catch (Exception error)
                {
                    System.Console.Error.WriteLine(error.ToString());
                }
            }

            System.Console.Out.WriteLine("GET https://localhost:7244");
            {
                using HttpClient client = new()
                {
                    BaseAddress = new Uri("https://localhost:7244")
                };

                try
                {
                    using var response = await client.GetAsync("https://localhost:7244");
                    response.EnsureSuccessStatusCode();
                    var responseBody = await response.Content.ReadAsStringAsync();
                    System.Console.Out.WriteLine(responseBody);
                }
                catch (Exception error)
                {
                    System.Console.Error.WriteLine(error.ToString());
                }
            }

            /*
            System.Console.WriteLine("Press Enter");
            System.Console.ReadLine();
            */
        }
        finally
        {
            if (sampleServerProcess is not null && !sampleServerProcess.HasExited)
            {
                sampleServerProcess.Kill();
            }
            if (frontEndProcess is not null && !frontEndProcess.HasExited)
            {
                frontEndProcess.Kill();
            }
            if (backEndProcess is not null && !backEndProcess.HasExited)
            {
                backEndProcess.Kill();
            }
        }


    }

}
