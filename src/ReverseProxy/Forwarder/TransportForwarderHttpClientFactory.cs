namespace Yarp.ReverseProxy.Forwarder;

internal sealed class TransportForwarderHttpClientFactory : ITransportForwarderHttpClientFactorySelector
{
    public const string TransportMode = "Forwarder";

    private readonly IForwarderHttpClientFactory _forwarderHttpClientFactory;

    public TransportForwarderHttpClientFactory(
        IForwarderHttpClientFactory forwarderHttpClientFactory
        )
    {
        _forwarderHttpClientFactory = forwarderHttpClientFactory;
    }

    public string GetTransportMode() => TransportMode;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(ForwarderHttpClientContext context)
    {
        return _forwarderHttpClientFactory;
    }
}
