using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Forwarder;

internal sealed class TransportForwarderHttpClientFactory : ITransportHttpClientFactorySelector
{
    private readonly IForwarderHttpClientFactory _forwarderHttpClientFactory;

    public TransportForwarderHttpClientFactory(
        IForwarderHttpClientFactory forwarderHttpClientFactory
        )
    {
        _forwarderHttpClientFactory = forwarderHttpClientFactory;
    }

    public TransportMode GetTransportMode() => TransportMode.Forwarder;

    public int GetOrder() => 0;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(TransportMode transportMode, ForwarderHttpClientContext context)
    {
        return _forwarderHttpClientFactory;
    }
}
