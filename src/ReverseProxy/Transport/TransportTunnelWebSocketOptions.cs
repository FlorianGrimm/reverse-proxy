// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.WebSockets;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Options for the transport WebSocket tunnel.
/// </summary>
public class TransportTunnelWebSocketOptions
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
    public Action<TransportTunnelConfig, ClientWebSocket, ITransportTunnelWebSocketAuthentication>? ConfigureClientWebSocket { get; set; }
}
