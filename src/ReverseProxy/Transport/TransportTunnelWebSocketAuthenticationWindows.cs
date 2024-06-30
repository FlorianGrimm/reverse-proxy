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

    public ValueTask<bool> ConfigureClientWebSocketAsync(TunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        if (!string.Equals(config.Authentication.Mode, "Windows", System.StringComparison.OrdinalIgnoreCase))
        {
            return new(false);
        }

        clientWebSocketocket.Options.Credentials = System.Net.CredentialCache.DefaultCredentials;
        return new(true);
    }
}
