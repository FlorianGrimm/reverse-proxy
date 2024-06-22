using System.Net.Http;
using System.Threading.Tasks;

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
public interface ITransportTunnelHttp2Authentication
{
    /// <summary>
    /// Authentification for the tunnel - configure the connection SocketsHttpHandler
    /// </summary>
    /// <param name="config">the related config</param>
    /// <param name="socketsHttpHandler">the used SocketsHttpHandler.</param>
    /// <returns>true the configuration is done and no other implemenation need to configure this.</returns>
    ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelConfig config, SocketsHttpHandler socketsHttpHandler);

    /// <summary>
    /// Authentification for the tunnel - configure the HttpRequestMessage
    /// </summary>
    /// <param name="config">the related config</param>
    /// <param name="requestMessage">the used message.</param>
    /// <returns>true the configuration is done and no other implemenation need to configure this.</returns>
    ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelConfig config, HttpRequestMessage requestMessage);
}
