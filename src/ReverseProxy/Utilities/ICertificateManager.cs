using System;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Allows to load certificates.
/// </summary>
public interface ICertificateManager
{
    /// <summary>
    /// Get the certificate collection defined by.
    /// </summary>
    /// <param name="certificateId">identifies the certificates to return (and may be load).</param>
    /// <returns>the (valid) certificates</returns>
    /// <remarks>
    /// Gives the opportunity to reuse your favorite library.
    /// </remarks>
    ISharedValue<X509Certificate2Collection?> GetCertificateCollection(string certificateId);
}
