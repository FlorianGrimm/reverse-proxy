using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelHttp2AuthenticationCertificate : ITransportTunnelHttp2Authentication
{
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TransportTunnelHttp2AuthenticationCertificate> _logger;

    public TransportTunnelHttp2AuthenticationCertificate(
        CertificatePathWatcher certificatePathWatcher,
        ILogger<TransportTunnelHttp2AuthenticationCertificate> logger
        )
    {
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;
    }


    public ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!(string.Equals(config.Authentication.Mode, "Certificate", System.StringComparison.OrdinalIgnoreCase)))
        {
            return new(false);
        }
        // TODO: Implement certificate authentication
        // borrow kerstel implementation for certificates?

#warning HELP pretty please I have no experiences with clientcertificates

        // List<X509Certificate>? listX509Certificate = null;

        // for in Memory Configuration
        if (config.Authentication.ClientCertifiacteCollection is { } srcClientCertifiacteCollection)
        {
            var clientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= new();
            clientCertificates.AddRange(srcClientCertifiacteCollection);
        }
        return new(true);
    }

    public ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        return new(false);
    }
}
