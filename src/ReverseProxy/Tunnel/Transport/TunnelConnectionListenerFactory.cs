using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Management;

// TODO: what exactly is a IConnectionListenerFactorySelector

namespace Yarp.ReverseProxy.Tunnel.Transport
{
    public class TunnelConnectionListenerFactory : IConnectionListenerFactory
#if NET8_0_OR_GREATER
        , IConnectionListenerFactorySelector
#endif
    {
        private readonly TunnelBackendOptions _options;
        private readonly IProxyTunnelStateLookup _proxyTunnelConfigManager;

        public TunnelConnectionListenerFactory(
            IOptions<TunnelBackendOptions> options,
            IProxyTunnelStateLookup proxyTunnelConfigManager
            )
        {
            _options = options.Value;
            _proxyTunnelConfigManager = proxyTunnelConfigManager;
        }

        public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
        {
            if (endpoint is not UriTunnelTransportEndPoint uriTunnelTransportEndPoint) {
                throw new NotSupportedException();
            }

            var tunnelId = uriTunnelTransportEndPoint.Uri?.Host;
            if (string.IsNullOrEmpty(tunnelId)) { throw new NotSupportedException(); }

            if (!_proxyTunnelConfigManager.TryGetTunnelBackendToFrontend(tunnelId, out var backendToFrontend)) {
                throw new NotSupportedException();
            }

            // TODO: more di
            TunnelConnectionListenerProtocol listener;
            if (backendToFrontend.Transport == "WebSocket")
            {
                listener = new TunnelConnectionListenerWebSocket(
                    uriTunnelTransportEndPoint,
                    tunnelId, backendToFrontend,
                    _proxyTunnelConfigManager,
                    _options
                    );
            }
            else
            {
                listener = new TunnelConnectionListenerHttp2(
                    uriTunnelTransportEndPoint,
                    tunnelId, backendToFrontend,
                    _proxyTunnelConfigManager,
                    _options
                    );
            }

            return new(listener);
        }

        public bool CanBind(EndPoint endpoint)
        {
            if (endpoint is not UriTunnelTransportEndPoint uriTunnelTransportEndPoint) {
                return false;
            }

            var tunnelId = uriTunnelTransportEndPoint.Uri?.Host;
            if (string.IsNullOrEmpty(tunnelId)) { return false; }

            return true;
        }
    }
}
