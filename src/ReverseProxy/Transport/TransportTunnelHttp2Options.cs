using System;
using System.Net.Http;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelHttp2Options
{
    public int MaxConnectionCount { get; set; } = 10;

    /// <summary>
    /// Authentification for the tunnel
    /// </summary>
    public Func<TunnelConfig, SocketsHttpHandler, ValueTask>? ConfigureSocketsHttpHandlerAsync { get; set; }

    /// <summary>
    /// Authentification for the tunnel
    /// </summary>
    public Func<TunnelConfig, HttpRequestMessage, ValueTask>? ConfigureHttpRequestMessageAsync { get; set; }
}
