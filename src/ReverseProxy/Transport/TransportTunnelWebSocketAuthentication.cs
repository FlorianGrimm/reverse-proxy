// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthentication(
        IEnumerable<ITransportTunnelWebSocketAuthentication> services
        ) : ITransportTunnelWebSocketAuthentication
{
    private readonly ImmutableDictionary<string, ITransportTunnelWebSocketAuthentication> _serviceByName = services.ToImmutableDictionary(service => service.GetAuthenticationName(), StringComparer.OrdinalIgnoreCase);

    public string GetAuthenticationName() => throw new NotSupportedException();

    public List<string> GetAuthenticationNames() => _serviceByName.Keys.ToList();

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
        var mode = config.Authentication.Mode;
        if (mode is { Length: > 0 }
            && _serviceByName.TryGetValue(mode, out var service))
        {
            service.ConfigureWebSocketConnectionOptions(config, options);
        }
        else
        {
            throw new NotSupportedException($"Authentication.Mode {mode} is unknown");
        }
    }

    public async ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        var mode = config.Authentication.Mode;
        if (mode is { Length: > 0 }
            && _serviceByName.TryGetValue(mode, out var service))
        {
            return await service.ConfigureClientWebSocket(config, clientWebSocketocket);
        }
        else
        {
            throw new NotSupportedException($"Authentication.Mode {mode} is unknown");
        }
    }
}
