using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Options;
using Microsoft.VisualBasic;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Represents a class that handles the loading of signing certificates for authentication transport.
/// </summary>
internal class AuthorizationTransportSigningCertificate
{
    private readonly AuthorizationTransportOptions _options;
    private readonly ICertificateManager _certificateManager;
    private readonly CertificateRequestCollection? _certificateRequestCollection;

    /// <summary>
    /// Creates a new instance of <see cref="AuthorizationTransportSigningCertificate"/>.
    /// </summary>
    /// <param name="certificateManager">certificateManager</param>
    /// <param name="options">Configuration options for the signing certificate.</param>
    public AuthorizationTransportSigningCertificate(
        ICertificateManager certificateManager,
        AuthorizationTransportOptions options)
    {
        _options = options;
        _certificateManager = certificateManager;

        if (options.SigningCertificateConfig is { } config)
        {
            _certificateRequestCollection = certificateManager.AddConfiguration(
                "AuthorizationTransportSigningCertificate",
                null,
                null,
                null,
                new CertificateRequirement()
                {
                    SignCertificate = true,
                });
            certificateManager.AddRequestCollection(_certificateRequestCollection);
        }
    }

    internal ISharedValue<X509Certificate2Collection?>? GetCertificate()
    {
        if (_certificateRequestCollection is null) {
            return null;
        }
        return _certificateManager.GetCertificateCollection(_certificateRequestCollection);
    }
}
