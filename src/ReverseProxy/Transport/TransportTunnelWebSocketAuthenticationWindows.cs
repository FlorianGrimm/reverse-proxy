// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.WebSockets;

using Yarp.ReverseProxy.Configuration;


using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http.Connections.Client;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticationWindows
    : ITransportTunnelWebSocketAuthentication
{
    private readonly ILogger<TransportTunnelWebSocketAuthenticationWindows> _logger;

    public TransportTunnelWebSocketAuthenticationWindows(
        ILogger<TransportTunnelWebSocketAuthenticationWindows> logger
        )
    {
        _logger = logger;
    }

    public string GetAuthenticationName() => "Windows";

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
