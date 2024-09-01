// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using Yarp.ReverseProxy.Model;

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
public interface ITransportTunnelHttp2Authenticator
{
    /// <summary>
    /// The name of the authentication.
    /// </summary>
    /// <returns>the unique name</returns>
    string GetAuthenticationName();

    /// <summary>
    /// Authentification for the tunnel - configure the connection SocketsHttpHandler
    /// </summary>
    /// <param name="tunnel">the current tunnel</param>
    /// <param name="socketsHttpHandler">the used SocketsHttpHandler.</param>
    /// <returns>true the configuration is done and no other implemenation need to configure this.</returns>
    ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler);

    /// <summary>
    /// Authentification for the tunnel - configure the HttpRequestMessage
    /// </summary>
    /// <param name="tunnel">the current tunnel</param>
    /// <param name="requestMessage">the used message.</param>
    /// <returns>true the configuration is done and no other implemenation need to configure this.</returns>
    ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage);
}
