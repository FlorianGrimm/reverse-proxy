using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Transport;
public class TunnelHttp2ConnectionListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector
{
    private readonly TunnelHttp2Options _options;

    public TunnelHttp2ConnectionListenerFactory(IOptions<TunnelHttp2Options> options)
    {
        _options = options.Value;
    }

    public bool CanBind(EndPoint endpoint)
    {
        return endpoint is UriEndPointHttp2;
    }

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not UriEndPointHttp2 uriEndPointHttp2)
        {
            throw new ArgumentException("Invalid endpoint type", nameof(endpoint));
        }
        else
        {
            return new(new TunnelHttp2ConnectionListener(_options, uriEndPointHttp2));
        }
    }
}
