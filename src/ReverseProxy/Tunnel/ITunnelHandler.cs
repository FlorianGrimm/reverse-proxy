using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

using Microsoft.AspNetCore.Routing;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

public interface ITunnelHandler
{
    bool TryGetTunnelConnectionChannel(SocketsHttpConnectionContext socketsContext, [MaybeNullWhen(false)] out ActiveTunnelConnection activeTunnel);

    void Map(IEndpointRouteBuilder endpoints);
    Dictionary<string, DestinationConfig> GetDestinations();
}
