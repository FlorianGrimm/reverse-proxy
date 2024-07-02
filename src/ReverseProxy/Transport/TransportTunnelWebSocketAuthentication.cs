// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthentication(
        IEnumerable<ITransportTunnelWebSocketAuthentication> services
        ) : ITransportTunnelWebSocketAuthentication
{
    public ImmutableArray<ITransportTunnelWebSocketAuthentication> Services { get; set; } = services.ToImmutableArray();

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
        var services = Services;
        foreach (var service in services)
        {
            service.ConfigureWebSocketConnectionOptions(config, options);
        }
    }

    public void ConfigureClientWebSocketAsync(TransportTunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        var services = Services;
        foreach (var service in services)
        {
            service.ConfigureClientWebSocketAsync(config, clientWebSocketocket);
        }
    }
}
