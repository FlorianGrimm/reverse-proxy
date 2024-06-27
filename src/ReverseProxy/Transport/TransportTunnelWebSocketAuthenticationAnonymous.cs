// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticationAnonymous
    : ITransportTunnelWebSocketAuthentication
{
    public ValueTask<bool> ConfigureClientWebSocketAsync(TunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        if (!string.Equals(config.Authentication.Mode, "Anonymous", StringComparison.InvariantCultureIgnoreCase))
        {
            return new(false);
        }
        return new(true);
    }
}
