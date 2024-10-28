#nullable enable

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Allows creating a new <see cref="YarpCertificateCollection"/> and load the certificates by the configuration.
/// </summary>
public interface IYarpCertificateCollectionFactory
{
    /// <summary>
    /// Creates a new YarpCertificateCollection - without the serivce parameters.
    /// </summary>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="loadWithPrivateKey">load with private key - or without if false.</param>
    /// <returns>the new YarpCertificateCollection.</returns>
    YarpCertificateCollection Create(string id, bool loadWithPrivateKey);

    /// <summary>
    /// Creates a new CertificateCollection and load the certificates by the configuration.
    /// </summary>
    /// <param name="certificateCollection">optional previous result</param>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="loadWithPrivateKey">load with private key - or without if false.</param>
    /// <param name="certificateConfig">configuration for loading the certificates.</param>
    /// <param name="listCertificateConfig">configuration for loading the certificates.</param>
    /// <param name="x509CertificateCollection">predefined certificates</param>
    /// <returns>the (new) CertificateCollection and load </returns>
    YarpCertificateCollection CreateAndLoad(
        YarpCertificateCollection? certificateCollection,
        string id,
        bool loadWithPrivateKey,
        CertificateConfig? certificateConfig,
        List<CertificateConfig>? listCertificateConfig,
        X509CertificateCollection? x509CertificateCollection
        );
}

/// <summary>
/// Allows creating a new CertificateCollection and load the certificates by the configuration.
/// </summary>
/// <param name="certificateLoader">The loader responsible for loading certificates.</param>
/// <param name="certificatePathWatcher">The watcher that monitors changes in the certificate path.</param>
/// <param name="timeProvider">The TimeProvider</param>
internal sealed class YarpCertificateCollectionFactory(
    IYarpCertificateLoader certificateLoader,
    IYarpCertificatePathWatcher? certificatePathWatcher,
        TimeProvider timeProvider
    ) : IYarpCertificateCollectionFactory
{
    private readonly IYarpCertificateLoader _certificateLoader = certificateLoader;
    private readonly IYarpCertificatePathWatcher? _certificatePathWatcher = certificatePathWatcher;

    /// <summary>
    /// Creates a new YarpCertificateCollection - without the serivce parameters.
    /// </summary>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="loadWithPrivateKey">load with private key - or without if false.</param>
    /// <returns>the new YarpCertificateCollection.</returns>
    public YarpCertificateCollection Create(
        string id,
        bool loadWithPrivateKey
        )
    {
        var result = new YarpCertificateCollection(
            _certificateLoader,
            _certificatePathWatcher,
            id,
            loadWithPrivateKey,
            timeProvider);

        return result;
    }

    /// <summary>
    /// Creates a new CertificateCollection and load the certificates by the configuration.
    /// </summary>
    /// <param name="certificateCollection">optional previous result</param>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="loadWithPrivateKey">load with private key - or without if false.</param>
    /// <param name="certificateConfig">configuration for loading the certificates.</param>
    /// <param name="listCertificateConfig">configuration for loading the certificates.</param>
    /// <param name="x509CertificateCollection">predefined certificates</param>
    /// <returns>the (new) CertificateCollection and load </returns>
    public YarpCertificateCollection CreateAndLoad(
        YarpCertificateCollection? certificateCollection,
        string id,
        bool loadWithPrivateKey,
        CertificateConfig? certificateConfig,
        List<CertificateConfig>? listCertificateConfig,
        X509CertificateCollection? x509CertificateCollection
        )
    {
        certificateCollection ??= new YarpCertificateCollection(
            _certificateLoader,
            _certificatePathWatcher,
            id,
            loadWithPrivateKey,
            timeProvider);

        var certificateCollectionRequest= new YarpCertificateCollection.LoadParameter
        {
            CertificateConfig = certificateConfig,
            ListCertificateConfig = listCertificateConfig,
            X509CertificateCollection = x509CertificateCollection
        };

        return certificateCollection.Load(certificateCollectionRequest);
    }
}
