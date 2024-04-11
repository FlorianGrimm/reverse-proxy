using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;

// TODO: what is a IConnectionListenerFactorySelector

namespace Yarp.ReverseProxy.Tunnel
{
    public class TunnelConnectionListenerFactory : IConnectionListenerFactory
    {
        private readonly TunnelOptions _options;
        private readonly IServiceProvider _serviceProvider;
        private IProxyStateLookup? _proxyStateLookup=null;

        public TunnelConnectionListenerFactory(IOptions<TunnelOptions> options, IServiceProvider serviceProvider)
        {
            _options = options.Value;
            _serviceProvider = serviceProvider;
        }

        public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
        {
            var proxyStateLookup = (_proxyStateLookup ??= _serviceProvider.GetRequiredService<IProxyStateLookup>());
            return new(new TunnelConnectionListener(_options, proxyStateLookup, endpoint));
        }
    }

    public class TunnelOptions {
        public int MaxConnectionCount { get; set; } = 10;
        
    }
    
}
