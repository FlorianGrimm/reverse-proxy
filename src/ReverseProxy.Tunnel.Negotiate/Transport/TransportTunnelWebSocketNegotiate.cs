// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketNegotiate
    : ITransportTunnelWebSocketAuthenticator
{
    private readonly ILogger<TransportTunnelWebSocketNegotiate> _logger;

    public TransportTunnelWebSocketNegotiate(
        ILogger<TransportTunnelWebSocketNegotiate> logger
        )
    {
        _logger = logger;
    }

    public string GetAuthenticationName()
        => Yarp.ReverseProxy.Tunnel.TunnelNegotiateConstants.NegotiateAuthenticationName;

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
        options.SkipNegotiation = true;
        options.UseDefaultCredentials = true;
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
    {
        clientWebSocket.Options.Credentials = System.Net.CredentialCache.DefaultCredentials;
        return ValueTask.FromResult<HttpMessageInvoker?>(default);
    }
}
