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
    /// Maximum number of connections to the (frontend) proxy.
    /// </summary>
    public int MaxConnectionCount { get; set; } = 10;

    /// <summary>
    /// Allows Authentification for the tunnel.
    /// </summary>
    public Action<TransportTunnelConfig, ClientWebSocket>? ConfigureClientWebSocket { get; set; }
}
