using System.Net.Http;
using System;
using System.Net.WebSockets;

namespace Yarp.ReverseProxy.Transport;

public class TunnelWebSocketOptions
{
    public int MaxConnectionCount { get; set; } = 10;

    public Action<Uri, ClientWebSocket>? ConfigureClientWebSocket { get; set; }
}
