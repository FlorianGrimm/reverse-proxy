using System;
using System.Net.WebSockets;
using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

public class TransportTunnelWebSocketOptions
{
    public int MaxConnectionCount { get; set; } = 10;

    public Action<TunnelConfig, ClientWebSocket>? ConfigureClientWebSocket { get; set; }
}
