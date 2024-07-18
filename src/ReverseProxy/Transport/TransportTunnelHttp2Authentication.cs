// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Calls all registered ITransportTunnelHttp2Authentication services.
/// </summary>
/// <param name="services">the known services.</param>
internal sealed class TransportTunnelHttp2Authentication(
    IEnumerable<ITransportTunnelHttp2Authentication> services
    ) : ITransportTunnelHttp2Authentication
{
    private readonly ImmutableDictionary<string, ITransportTunnelHttp2Authentication> _serviceByName = services.ToImmutableDictionary(service => service.GetAuthenticationName(), StringComparer.OrdinalIgnoreCase);

    public string GetAuthenticationName() => throw new NotSupportedException();

    public List<string> GetAuthenticationNames() => _serviceByName.Keys.ToList();

    public async ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var mode = tunnel.Model.Config.Authentication.Mode;
        if (mode is { Length: > 0 }
            && _serviceByName.TryGetValue(mode, out var service))
        {
            return await service.ConfigureSocketsHttpHandlerAsync(tunnel, socketsHttpHandler);
        }
        else
        {
            return null;
        }
    }

    public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        var mode = tunnel.Model.Config.Authentication.Mode;
        if (mode is { Length: > 0 }
            && _serviceByName.TryGetValue(mode, out var service))
        {
            await service.ConfigureHttpRequestMessageAsync(tunnel, requestMessage);
        }
    }
}
