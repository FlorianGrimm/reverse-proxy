// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticationNegotiate
    : ITransportTunnelWebSocketAuthentication
{
    private readonly ILogger<TransportTunnelWebSocketAuthenticationNegotiate> _logger;

    public TransportTunnelWebSocketAuthenticationNegotiate(
        ILogger<TransportTunnelWebSocketAuthenticationNegotiate> logger
        )
    {
        _logger = logger;
    }

    public string GetAuthenticationName() => "Negotiate";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
        options.Credentials = System.Net.CredentialCache.DefaultCredentials;
        options.SkipNegotiation = false;
        options.UseDefaultCredentials = true;
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
    {
        clientWebSocket.Options.Credentials = System.Net.CredentialCache.DefaultCredentials;
        return ValueTask.FromResult<HttpMessageInvoker?>(default);
    }
}
