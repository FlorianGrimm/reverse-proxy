using System;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelHTTP2MapHandlerFactory : ITunnelHandlerFactory
{
    private readonly IServiceProvider _serviceProvider;
    private IForwarderHttpClientFactorySelector? _forwarderHttpClientFactorySelector;
    private ProxyTunnelConfigManager? _proxyTunnelConfigManager;
    private ILogger<TunnelHTTP2MapHandler>? _loggerTunnelHTTP2MapHandler = null;

    public TunnelHTTP2MapHandlerFactory(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public bool CanCreate(string transport)
    {
        return string.Equals(transport, "TunnelHTTP2", StringComparison.OrdinalIgnoreCase);
    }

    public ITunnelHandler Create(TunnelFrontendToBackendState tunnelFrontendToBackend)
    {
        if (tunnelFrontendToBackend.TryGetForwarderHttpClientFactory(
            _forwarderHttpClientFactorySelector ??= _serviceProvider.GetRequiredService<IForwarderHttpClientFactorySelector>(),
            out var forwarderHttpClientFactory))
        {
            _proxyTunnelConfigManager ??= _serviceProvider.GetRequiredService<ProxyTunnelConfigManager>();

            _loggerTunnelHTTP2MapHandler ??= _serviceProvider.GetRequiredService<ILogger<TunnelHTTP2MapHandler>>();

            return new TunnelHTTP2MapHandler(
                _proxyTunnelConfigManager,
                tunnelFrontendToBackend,
                forwarderHttpClientFactory,
                _loggerTunnelHTTP2MapHandler);
        }
        else
        {
            throw new NotSupportedException();
        }

    }
}
