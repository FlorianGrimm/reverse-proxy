using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Configuration;

public class ClusterTunnelConfig
{
    public int MaxConnectionCount { get; set; } = 10;

    public TransportType Transport { get; set; }
}
