using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal class TransportTunnelWebSocketAuthenticationJwtBearer
    : ITransportTunnelWebSocketAuthentication
{
    public string GetAuthenticationName() => "JwtBearer";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        return ValueTask.FromResult<HttpMessageInvoker?>(default);
    }
}
