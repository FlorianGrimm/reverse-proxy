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
#if NET8_0_OR_GREATER
        , IConnectionListenerFactorySelector
#endif
    {
        private readonly TunnelBackendOptions _options;
        private readonly IServiceProvider _serviceProvider;
        private IProxyStateLookup? _proxyStateLookup = null;

        public TunnelConnectionListenerFactory(IOptions<TunnelBackendOptions> options, IServiceProvider serviceProvider)
        {
            _options = options.Value;
            _serviceProvider = serviceProvider;
        }

        public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
        {
            if (endpoint is not UriTunnelTransportEndPoint uriTunnelTransportEndPoint) { throw new NotSupportedException(); }

            var tunnelId = uriTunnelTransportEndPoint.Uri?.Host;
            if (string.IsNullOrEmpty(tunnelId)) { throw new NotSupportedException(); }

            var proxyStateLookup = (_proxyStateLookup ??= _serviceProvider.GetRequiredService<IProxyStateLookup>());
            if (!proxyStateLookup.TryGetTunnelBackendToFrontend(tunnelId, out var backendToFrontend)) { throw new NotSupportedException(); }

            return new(new TunnelConnectionListener(
                uriTunnelTransportEndPoint,
                tunnelId, backendToFrontend, proxyStateLookup,
                _options
                ));
        }

        public bool CanBind(EndPoint endpoint)
        {
            if (endpoint is not UriTunnelTransportEndPoint uriTunnelTransportEndPoint) { return false; }

            var tunnelId = uriTunnelTransportEndPoint.Uri?.Host;
            if (string.IsNullOrEmpty(tunnelId)) { return false; }

#warning TODO: may be it's better to create a IProxyTransportStateLookup, the problems of the timing might be to big
            //var proxyStateLookup = (_proxyStateLookup ??= _serviceProvider.GetRequiredService<IProxyStateLookup>());
            //if (!proxyStateLookup.TryGetTunnelBackendToFrontend(tunnelId, out var backendToFrontend)) { return false; }

            //return (backendToFrontend is not null);
            return true;
        }
    }

    public class TunnelBackendOptions
    {
        public int MaxConnectionCount { get; set; } = 10;

    }

}
