using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SampleTunnelFourInOne;

public class ServerBase
{
    protected WebApplication _app;

    public IHostApplicationLifetime Lifetime => _app.Services.GetRequiredService<IHostApplicationLifetime>();

    public ServerBase(WebApplication app)
    {
        _app = app;
    }

    public async Task RunAsync()
    {
        await _app.RunAsync();
    }
}
