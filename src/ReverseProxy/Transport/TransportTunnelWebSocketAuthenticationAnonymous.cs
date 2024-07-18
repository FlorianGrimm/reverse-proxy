// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticationAnonymous
    : ITransportTunnelWebSocketAuthentication
{
    public string GetAuthenticationName() => "Anonymous";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
        => ValueTask.FromResult<HttpMessageInvoker?>(default);
}
