// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelLoopbackAuthenticator(
    IEnumerable<ITransportTunnelLoopbackAuthenticator> services
    ) : ITransportTunnelLoopbackAuthenticator
{
    private readonly ImmutableDictionary<string, ITransportTunnelLoopbackAuthenticator> _serviceByName = services.ToImmutableDictionary(service => service.GetAuthenticationName(), StringComparer.OrdinalIgnoreCase);

    public string GetAuthenticationName() => throw new NotSupportedException();

    public List<string> GetAuthenticationNames() => _serviceByName.Keys.ToList();

    public async ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var mode = tunnel.Model.Config.TransportAuthentication.Mode;
        if (mode is { Length: > 0 }
            && _serviceByName.TryGetValue(mode, out var service))
        {
            return await service.ConfigureSocketsHttpHandlerAsync(tunnel, socketsHttpHandler);
        }
        else
        {
            var knownAuthenticationModes = string.Join(", ", _serviceByName.Keys);
            throw new NotSupportedException($"Authentication.Mode {mode} is unknown. known AuthenticationModes:{knownAuthenticationModes}");
        }
    }

    public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        var mode = tunnel.Model.Config.TransportAuthentication.Mode;
        if (mode is { Length: > 0 }
            && _serviceByName.TryGetValue(mode, out var service))
        {
            await service.ConfigureHttpRequestMessageAsync(tunnel, requestMessage);
        }
        else
        {
            throw new NotSupportedException($"Authentication.Mode {mode} is unknown");
        }
    }
}

// TODO: Until i know what I want
internal class TransportTunnelLoopbackAuthenticatorLoopback : ITransportTunnelLoopbackAuthenticator
{
    public string GetAuthenticationName() => "Loopback";

    public ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        return ValueTask.CompletedTask;
    }

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        return ValueTask.FromResult<HttpMessageInvoker?>(null);
    }

}
