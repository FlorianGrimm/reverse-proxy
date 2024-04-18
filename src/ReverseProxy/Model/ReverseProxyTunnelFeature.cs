namespace Yarp.ReverseProxy.Model;
public interface IReverseProxyTunnelFeature
{
    public TunnelFrontendToBackendState TunnelFrontendToBackend { get; } 
}
public class ReverseProxyTunnelFeature : IReverseProxyTunnelFeature
{
    public TunnelFrontendToBackendState TunnelFrontendToBackend { get; init; } = default!;
}
