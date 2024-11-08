// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Net.WebSockets;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Authentication for Http2 tunnels.
/// </summary>
/// <example>
/// register like this:
/// <code>
/// builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton&lt;ITransportTunnelHttp2Authentication, YourImplementation&gt;());
/// </code>
/// </example>
public interface ITransportTunnelWebSocketAuthenticator
{
    /// <summary>
    /// The name of the authentication.
    /// </summary>
    /// <returns>the unique name</returns>
    string GetAuthenticationName();

    void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options);

    /// <summary>
    /// Authentication for the tunnel - configure the connection ClientWebSocket
    /// </summary>
    /// <param name="config">the related config</param>
    /// <param name="clientWebSocketocket">the used ClientWebSocket.</param>
    /// <returns>the HttpMessageInvoker if needed.</returns>
    ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocketocket);
}
