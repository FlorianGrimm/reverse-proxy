using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// TODO
/// </summary>
/// <param name="ClientCertificate">TODO</param>
/// <param name="SignCertificate">TODO</param>
/// <param name="NeedPrivateKey">TODO</param>
/// <param name="AllowCertificateSelfSigned">TODO</param>
/// <param name="RevocationFlag">TODO</param>
/// <param name="RevocationMode">TODO</param>
/// <param name="VerificationFlags">TODO</param>
/// <param name="ValidateValidityPeriod">TODO</param>
/// <param name="TrustMode">The mode determining the root trust for building the certificate chain.</param>
/// <param name="CustomTrustStore">Represents a collection of certificates replacing the default certificate trust.</param>
/// <param name="AdditionalChainCertificates">TODO</param>
public record struct CertificateRequirement(
    bool ClientCertificate = default,
    bool SignCertificate = default,
    bool NeedPrivateKey = default,

    bool AllowCertificateSelfSigned = default,

    X509RevocationFlag? RevocationFlag = default,
    X509RevocationMode? RevocationMode = default,
    X509VerificationFlags? VerificationFlags = default,

    bool? ValidateValidityPeriod = default,
    X509ChainTrustMode? TrustMode = default,
    X509Certificate2Collection? CustomTrustStore = default,
    X509Certificate2Collection? AdditionalChainCertificates = default
    );
