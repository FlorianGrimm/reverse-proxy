using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

public interface ITunnelHandler
{
    bool TryGetTunnelConnectionChannel(SocketsHttpConnectionContext socketsContext, [MaybeNullWhen(false)] out TunnelConnectionChannel tunnelConnectionChannel);

    IEndpointConventionBuilder Map(IEndpointRouteBuilder endpoints);

    Dictionary<string, DestinationConfig> GetDestinations();

    string GetTransport();
}
