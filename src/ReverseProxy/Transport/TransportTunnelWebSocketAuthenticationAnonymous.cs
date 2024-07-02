// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;


#warning not very usefull - remove it??

internal sealed class TransportTunnelWebSocketAuthenticationAnonymous
    : ITransportTunnelWebSocketAuthentication
{
    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public void ConfigureClientWebSocketAsync(TransportTunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        //if (!string.Equals(config.Authentication.Mode, "Anonymous", StringComparison.InvariantCultureIgnoreCase))
        //{
        //    return ;
        //}
    }
}
