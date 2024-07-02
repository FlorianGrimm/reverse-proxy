// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelHttp2AuthenticationWindows
    : ITransportTunnelHttp2Authentication
{

    public TransportTunnelHttp2AuthenticationWindows() { }


    public ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!string.Equals(config.Authentication.Mode, "Windows", System.StringComparison.OrdinalIgnoreCase))
        {
            return new(false);
        }
        socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
        return new(true);
    }

    public ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        return new(false);
    }
}
