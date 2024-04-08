using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel.Transport;

public class TunnelConnectionListenerFactory : IConnectionListenerFactory
{
    private readonly TunnelBackendConfig _options;

    public TunnelConnectionListenerFactory(IOptions<TunnelBackendConfig> options)
    {
        _options = options.Value;
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        return new(new TunnelConnectionListener(_options, endpoint));
    }
}
