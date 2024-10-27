using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal class AuthenticationTransportSigningCertificate
{
    private readonly IYarpCertificateLoader _certificateLoader;
    private readonly YarpCertificatePathWatcher? _certificatePathWatcher;
    private readonly AuthorizationTransportOptions _options;
    private readonly YarpCertificateCollection _certificateCollection;

    public AuthenticationTransportSigningCertificate(IYarpCertificateLoader certificateLoader, YarpCertificatePathWatcher? certificatePathWatcher, AuthorizationTransportOptions options)
    {
        _certificateLoader = certificateLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _options = options;
        _certificateCollection = new YarpCertificateCollection(_certificateLoader, _certificatePathWatcher, "SigningCertificate");
    }

    public Shared<X509CertificateCollection?>? GetCertificate()
    {
        if (_options.SigningCertificateConfig is { } config)
        {
            var shareCollection = _certificateCollection.Load(config, default, default).Share();
            if (shareCollection.Value is { Count: > 0 } )
            {
                return shareCollection;
            }
        }
        return null;
    }
}
