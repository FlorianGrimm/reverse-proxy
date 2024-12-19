// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

public interface ITransportTunnelLoopbackAuthenticator
{
    /// <summary>
    /// The name of the authentication.
    /// </summary>
    /// <returns>the unique name</returns>
    string GetAuthenticationName();

    /// <summary>
    /// Authentication for the tunnel - configure the connection SocketsHttpHandler
    /// </summary>
    /// <param name="tunnel">the current tunnel</param>
    /// <param name="socketsHttpHandler">the used SocketsHttpHandler.</param>
    /// <returns>true the configuration is done and no other implementation need to configure this.</returns>
    ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler);

    /// <summary>
    /// Authentication for the tunnel - configure the HttpRequestMessage
    /// </summary>
    /// <param name="tunnel">the current tunnel</param>
    /// <param name="requestMessage">the used message.</param>
    /// <returns>true the configuration is done and no other implementation need to configure this.</returns>
    ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage);
}
