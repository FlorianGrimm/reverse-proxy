// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;
internal sealed class TransportTunnelHttp2AuthenticationAnonymous
    : ITransportTunnelHttp2Authentication
{
    public ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        if (!string.Equals(tunnel.Model.Config.Authentication.Mode, "Anonymous", StringComparison.InvariantCultureIgnoreCase))
        {
            return new(false);
        }
        return new(true);
    }

    public ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        if (!string.Equals(tunnel.Model.Config.Authentication.Mode, "Anonymous", StringComparison.InvariantCultureIgnoreCase))
        {
            return new(false);
        }
        return new(true);
    }
}
