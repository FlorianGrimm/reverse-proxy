using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Represents a class that handles the loading of signing certificates for authentication transport.
/// </summary>
/// <param name="certificateCollectionFactory">Factory.</param>
/// <param name="options">Configuration options for the signing certificate.</param>
internal class AuthorizationTransportSigningCertificate(
    IYarpCertificateCollectionFactory certificateCollectionFactory,
    AuthorizationTransportOptions options)
{
    private readonly YarpCertificateCollection _certificateCollection = certificateCollectionFactory.CreateAndLoad(
        null,
        "SigningCertificate",
        true,
        options.SigningCertificateConfig, null, null
        );

    internal Shared<X509CertificateCollection?>? GetCertificate()
    {
        if (options.SigningCertificateConfig is not { } config)
        {
            return null;
        }

        var shareCollection = _certificateCollection
            .Load(config, default, default)
            .Share();
        if (shareCollection.Value is { Count: > 0 } )
        {
            return shareCollection;
        }

        shareCollection.Dispose();
        return null;
    }
}
