#nullable enable

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Allows creating a new CertificateCollection and load the certificates by the configuration.
/// </summary>
public interface ICertificateCollectionFactory
{
    /// <summary>
    /// Creates a new CertificateCollection and load the certificates by the configuration.
    /// </summary>
    /// <param name="certificateCollection">optional previous result</param>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="certificateCollectionRequest">configuration for loading the certificates.</param>
    /// <returns>the (new) CertificateCollection and load </returns>
    YarpCertificateCollection Create(
        YarpCertificateCollection? certificateCollection,
        string id,
        YarpCertificateCollection.LoadParameter certificateCollectionRequest
        );
}

/// <summary>
/// Allows creating a new CertificateCollection and load the certificates by the configuration.
/// </summary>
internal sealed class CertificateCollectionFactory(
    IYarpCertificateLoader certificateLoader,
    YarpCertificatePathWatcher? certificatePathWatcher
    ) : ICertificateCollectionFactory
{
    private readonly IYarpCertificateLoader _certificateLoader = certificateLoader;
    private readonly YarpCertificatePathWatcher? _certificatePathWatcher = certificatePathWatcher;

    /// <summary>
    /// Creates a new CertificateCollection and load the certificates by the configuration.
    /// </summary>
    /// <param name="certificateCollection">optional previous result</param>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="certificateCollectionRequest">configuration for loading the certificates.</param>
    /// <returns>the (new) CertificateCollection and load </returns>
    public YarpCertificateCollection Create(
        YarpCertificateCollection? certificateCollection,
        string id,
        YarpCertificateCollection.LoadParameter certificateCollectionRequest
        )
    {
        certificateCollection ??= new YarpCertificateCollection(_certificateLoader, _certificatePathWatcher, id);
        return certificateCollection.Load(certificateCollectionRequest);
    }
}
