// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Http;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Options for the transport HTTP/2 tunnel.
/// </summary>
public sealed class TransportTunnelHttp2Options
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
    /// Allows Authentification for the tunnel.
    /// </summary>
    public Func<TransportTunnelConfig, SocketsHttpHandler, ValueTask>? ConfigureSocketsHttpHandlerAsync { get; set; }

    /// <summary>
    /// Allows Authentification for the tunnel.
    /// </summary>
    public Func<TransportTunnelConfig, HttpRequestMessage, ValueTask>? ConfigureHttpRequestMessageAsync { get; set; }
}
