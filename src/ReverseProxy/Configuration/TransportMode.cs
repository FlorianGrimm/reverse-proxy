using System;

namespace Yarp.ReverseProxy.Configuration;

public enum TransportMode
{
    Invalid = -1,
    Forwarder = 0,
    TunnelHTTP2 = 1,
    TunnelWebSocket = 2
}
