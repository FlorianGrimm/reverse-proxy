namespace Yarp.ReverseProxy.Forwarder;

/// <summary>
/// Interface for selecting the appropriate HTTP client factory for a transport forwarder.
/// </summary>
public interface ITransportForwarderHttpClientFactorySelector
{
    /// <summary>
    /// Gets the transport mode used by the forwarder.
    /// </summary>
    /// <returns>A string representing the transport mode (e.g. "Forwarder", "TunnelHTTP2", "TunnelWebSocket").</returns>
    string GetTransport();

    /// <summary>
    /// Gets the appropriate HTTP client factory based on the provided context.
    /// </summary>
    /// <param name="context">The context for which the HTTP client factory is needed.</param>
    /// <returns>An instance of <see cref="IForwarderHttpClientFactory"/> if available; otherwise, null.</returns>
    IForwarderHttpClientFactory? GetForwarderHttpClientFactory(ForwarderHttpClientContext context);
}
