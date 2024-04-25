using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

public interface ITunnelHandlerFactory
{
    bool CanCreate(string transport);

    ITunnelHandler? Create(TunnelFrontendToBackendState tunnelFrontendToBackend);
}
