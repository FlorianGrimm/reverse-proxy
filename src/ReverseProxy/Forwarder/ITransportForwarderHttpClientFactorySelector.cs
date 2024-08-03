namespace Yarp.ReverseProxy.Forwarder;

public interface ITransportForwarderHttpClientFactorySelector
{
    string GetTransportMode();

    IForwarderHttpClientFactory? GetForwarderHttpClientFactory(ForwarderHttpClientContext context);
}
