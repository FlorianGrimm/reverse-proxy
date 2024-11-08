using System;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Allows to load certificates.
/// <see cref="CertificateManagerOptions"/> is used to configure this.
/// </summary>
public interface ICertificateManager
{
    /// <summary>
    /// Add the CertificateRequestCollection to enable <see cref="GetCertificateCollection(CertificateRequestCollection)"/>.
    /// </summary>
    /// <param name="requestCollection">defines the parameter the certificates</param>
    /// <returns>a <see cref="System.IDisposable"/> to remove the requestCollection.</returns>
    IDisposable AddRequestCollection(CertificateRequestCollection requestCollection);

    /// <summary>
    /// Get the certificate collection defined by <paramref name="requestCollection"/>.
    /// </summary>
    /// <param name="requestCollection">defines the certificates to return (and may be load).</param>
    /// <returns>the (valid) certificates</returns>
    /// <remarks>
    /// <see cref="AddRequestCollection(CertificateRequestCollection)"/> must be called before.
    /// </remarks>
    ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequestCollection requestCollection);

    /// <summary>
    /// Remove the CertificateRequestCollection.
    /// </summary>
    /// <param name="requestCollection">defines the parameter the certificates</param>
    /// <returns>true - removed; false - not removed, because it was already removed or not added.</returns>
    bool RemoveRequestCollection(CertificateRequestCollection requestCollection);

    /// <summary>
    /// Refresh(reload) the certificates.
    /// </summary>
    /// <param name="force">false - only if needed; true - always</param>
    void Refresh(bool force);
}

/// <summary>
/// internal not for public use.
/// </summary>
public interface ICertificateManagerInternal : ICertificateManager
{
    /// <summary>
    /// internal not for public use.
    /// </summary>
    CertificateRequest AddRequest(CertificateRequest request);

    /// <summary>
    /// internal not for public use.
    /// </summary>
    ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequest request);
}
