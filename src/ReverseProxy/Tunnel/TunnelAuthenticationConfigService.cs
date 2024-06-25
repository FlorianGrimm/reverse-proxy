using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationConfigService
    : ITunnelAuthenticationConfigService
{
    private readonly List<ITunnelAuthenticationConfigService> _services;

    public TunnelAuthenticationConfigService(
        IEnumerable<ITunnelAuthenticationConfigService> listTunnelAuthenticationConfigService)
    {
        _services = listTunnelAuthenticationConfigService.ToList();
    }

    public bool Configure(SocketsHttpHandler socketsHttpHandler, TunnelAuthenticationConfig authentication)
    {
        foreach (var service in _services)
        {
            if (service.Configure(socketsHttpHandler, authentication))
            {
                return true;
            }
        }
        return false;
    }
}
