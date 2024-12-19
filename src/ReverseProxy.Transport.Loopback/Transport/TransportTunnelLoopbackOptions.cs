using System;
using System.Net.Http;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Options for tunnel Loopback
/// </summary>
public sealed class TransportTunnelLoopbackOptions
{
    /// <summary>
    /// Enables or disables the transport.
    /// Enable has the effect that the KestrelServerOptions.Listen is called.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Maximum number of connections to the (frontend) proxy.
    /// </summary>
    public int MaxConnectionCount { get; set; } = 10;

    /// <summary>
    /// Allows Authentication for the tunnel.
    /// </summary>
    public Func<TransportTunnelConfig, SocketsHttpHandler, ITransportTunnelLoopbackAuthenticator, ValueTask>? ConfigureSocketsHttpHandlerAsync { get; set; }

    /// <summary>
    /// Allows Authentication for the tunnel.
    /// </summary>
    public Func<TransportTunnelConfig, HttpRequestMessage, ValueTask>? ConfigureHttpRequestMessageAsync { get; set; }
}
