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
    private readonly ICertificateConfigLoader _certificateConfigLoader;
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TransportTunnelHttp2AuthenticationCertificate> _logger;

    public TransportTunnelHttp2AuthenticationCertificate(
        ICertificateConfigLoader certificateConfigLoader,
        CertificatePathWatcher certificatePathWatcher,
        ILogger<TransportTunnelHttp2AuthenticationCertificate> logger
        )
    {
        _certificateConfigLoader = certificateConfigLoader;
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

        // config
        {
            if (config.Authentication.ClientCertificates is { Count: > 0 } clientCertificates)
            {
                for (var index = 0; index < clientCertificates.Count; index++)
                {
                    var clientCertificateConfig = clientCertificates[index];
                    var (certificate, collection) = _certificateConfigLoader.LoadCertificate(clientCertificateConfig, $"{config.TunnelId}/{index}", true);
                    if (certificate is not null)
                    {
                        var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= new();
                        sslClientCertificates.Add(certificate);
                    }

                    if (clientCertificateConfig.IsFileCert)
                    {
                        _certificatePathWatcher.AddWatchUnsynchronized(clientCertificateConfig);
                    }
                }
            }
        }

        // for in Memory Configuration
        {
            if (config.Authentication.ClientCertifiacteCollection is { } srcClientCertifiacteCollection)
            {
                var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= new();
                sslClientCertificates.AddRange(srcClientCertifiacteCollection);
            }
        }
        return new(true);
    }

    public ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        return new(false);
    }
}
