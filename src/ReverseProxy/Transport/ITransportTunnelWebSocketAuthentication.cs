// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Authentification for Http2 tunnels.
/// </summary>
/// <example>
/// register like this:
/// <code>
/// builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton&lt;ITransportTunnelHttp2Authentication, YourImplementation&gt;());
/// </code>
/// </example>
public interface ITransportTunnelWebSocketAuthentication
{
#warning TODO add selector

    void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options);

    /// <summary>
    /// Authentification for the tunnel - configure the connection ClientWebSocket
    /// </summary>
    /// <param name="config">the related config</param>
    /// <param name="clientWebSocketocket">the used ClientWebSocket.</param>
    /// <returns>true the configuration is done and no other implemenation need to configure this.</returns>
    void ConfigureClientWebSocketAsync(TransportTunnelConfig config, ClientWebSocket clientWebSocketocket);
}
