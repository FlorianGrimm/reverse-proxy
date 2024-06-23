using System.Net.Http;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

public class TransportTunnelHttp2AuthenticationCertificate : ITransportTunnelHttp2Authentication
{
    public TransportTunnelHttp2AuthenticationCertificate()
    {
    }


    public ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelConfig config, SocketsHttpHandler socketsHttpHandler)
    {
        if (!(string.Equals(config.Authentication.Mode , "Certificate", System.StringComparison.OrdinalIgnoreCase)))
        {
            return new(false);
        }
        //TODO: Implement certificate authentication
        // borrow kerstel implementation for certificates?

        // for in Memory Configuration
        if (config.Authentication.ClientCertifiacteCollection is { } srcClientCertifiacteCollection) {
            var clientCertificates =  socketsHttpHandler.SslOptions.ClientCertificates ??= new ();
            clientCertificates.AddRange(srcClientCertifiacteCollection);
        }
        return new(true);
    }

    public ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelConfig config, HttpRequestMessage requestMessage)
    {
        return new(false);
    }
}
