using System;

namespace Yarp.ReverseProxy.Configuration;

public enum TransportMode
{
    Invalid = 0,
    Forwarder = 1,
    TunnelHTTP2 = 2,
    TunnelWebSocket = 3
}
