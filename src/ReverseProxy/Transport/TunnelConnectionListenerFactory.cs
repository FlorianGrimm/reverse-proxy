using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Transport;
public class TunnelConnectionListenerFactory : IConnectionListenerFactory
{
    private readonly TunnelOptions _options;

    public TunnelConnectionListenerFactory(IOptions<TunnelOptions> options)
    {
        _options = options.Value;
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        return new(new TunnelConnectionListener(_options, endpoint));
    }
}
