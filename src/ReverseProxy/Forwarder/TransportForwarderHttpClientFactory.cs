namespace Yarp.ReverseProxy.Forwarder;

/// <summary>
/// This is a trampoline to the original IForwarderHttpClientFactory 
/// </summary>
internal sealed class TransportForwarderHttpClientFactory(
        IForwarderHttpClientFactory forwarderHttpClientFactory
    ) : ITransportForwarderHttpClientFactorySelector
{
    private readonly IForwarderHttpClientFactory _forwarderHttpClientFactory = forwarderHttpClientFactory;

    public string GetTransport()
        => Yarp.ReverseProxy.Tunnel.TunnelConstants.TransportNameForwarder;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(ForwarderHttpClientContext context)
        => _forwarderHttpClientFactory;
}
