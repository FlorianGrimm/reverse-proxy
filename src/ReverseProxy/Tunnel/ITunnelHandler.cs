using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// TunnelHandler for frontend to backend tunneling.
/// </summary>
public interface ITunnelHandler
{
    /// <summary>
    /// Get the transport name for the tunnel.
    /// </summary>
    /// <returns></returns>
    string GetTransport();

    /// <summary>
    /// Map the tunnel handler to the endpoint.
    /// </summary>
    /// <param name="endpoints"></param>
    /// <returns></returns>
    IEndpointConventionBuilder Map(IEndpointRouteBuilder endpoints);

    Dictionary<string, DestinationConfig> GetDestinations();

    bool TryGetTunnelConnectionChannel(SocketsHttpConnectionContext socketsContext, [MaybeNullWhen(false)] out TunnelConnectionChannel tunnelConnectionChannel);
}
