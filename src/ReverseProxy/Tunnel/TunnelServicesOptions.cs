// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelServicesOptions
{
    /// <summary>
    /// Enables or disables the HTTP/2 tunnel.
    /// Enable has the effect that the required services are added.
    /// </summary>
    public bool TunnelHTTP2 { get; set; } = true;

    /// <summary>
    /// Enables or disables the WebSocket tunnel.
    /// Enable has the effect that the required services are added.
    /// </summary>
    public bool TunnelWebSocket { get; set; } = true;
}
