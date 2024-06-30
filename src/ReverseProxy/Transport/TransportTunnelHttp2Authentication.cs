// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Threading.Tasks;

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
    /// <summary>
    /// the services.
    /// </summary>
    public ImmutableArray<ITransportTunnelHttp2Authentication> Services { get; set; } = services.ToImmutableArray();

    public async ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var services = Services;
        foreach (var service in services)
        {
            if (await service.ConfigureSocketsHttpHandlerAsync(tunnel, socketsHttpHandler))
            {
                return true;
            }
        }
        return false;
    }

    public async ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        var services = Services;
        foreach (var service in services)
        {
            if (await service.ConfigureHttpRequestMessageAsync(tunnel, requestMessage))
            {
                return true;
            }
        }
        return false;
    }

}
