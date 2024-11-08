using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Parameter for creating a <see cref="CertificateRequestCollection"/>.
/// </summary>
/// <param name="Id">the identifier for this definition.</param>
/// <param name="CertificateConfig">A <see cref="CertificateConfig"/>.</param>
/// <param name="CertificateConfigs">A list of <see cref="CertificateConfig"/>.</param>
/// <param name="CertificateCollection">A list of certificates.</param>
/// <param name="CertificateRequirement">The requirement.</param>
public record struct CertificateRequestCollectionParameter(
    string Id,
    CertificateConfig? CertificateConfig,
    List<CertificateConfig>? CertificateConfigs,
    X509Certificate2Collection? CertificateCollection,
    CertificateRequirement? CertificateRequirement = default
    )
{
    /// <summary>
    /// Checks if the parameter is empty.
    /// </summary>
    public bool IsEmpty()
        => (CertificateConfig is null)
        && ((CertificateConfigs is null) ? true : 0 == CertificateConfigs.Count)
        && ((CertificateCollection is null) ? true : 0 == CertificateCollection.Count)
        ;
}
