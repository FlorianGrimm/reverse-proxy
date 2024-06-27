// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.WebSockets;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelWebSocketAuthenticationCertificate
    : ITransportTunnelWebSocketAuthentication
{
    public TransportTunnelWebSocketAuthenticationCertificate()
    {

    }
    public ValueTask<bool> ConfigureClientWebSocketAsync(TunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        if (!(string.Equals(config.Authentication.Mode, "ClientCertificate", System.StringComparison.OrdinalIgnoreCase)))
        {
            return new(false);
        }
        //TODO: Implement certificate authentication
        // borrow kerstel implementation for certificates?

        // for in Memory Configuration
        if (config.Authentication.ClientCertifiacteCollection is { } srcClientCertifiacteCollection)
        {
            var clientCertificates = clientWebSocketocket.Options.ClientCertificates ??= new();
            clientCertificates.AddRange(srcClientCertifiacteCollection);
        }
        return new(false);
    }
}
