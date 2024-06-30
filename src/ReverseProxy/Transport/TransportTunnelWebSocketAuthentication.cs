// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthentication(
        IEnumerable<ITransportTunnelWebSocketAuthentication> services
        ) : ITransportTunnelWebSocketAuthentication
{
    public ImmutableArray<ITransportTunnelWebSocketAuthentication> Services { get; set; } = services.ToImmutableArray();

    public async ValueTask<bool> ConfigureClientWebSocketAsync(TunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        var services = Services;
        foreach (var service in services)
        {
            if (await service.ConfigureClientWebSocketAsync(config, clientWebSocketocket))
            {
                return true;
            }
        }
        return false;
    }
}
