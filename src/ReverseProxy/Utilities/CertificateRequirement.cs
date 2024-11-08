using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Defines the requirements for a certificate.
/// </summary>
/// <param name="ClientCertificate">Enhanced Key Usage must have Client Authentication (1.3.6.1.5.5.7.3.2)</param>
/// <param name="SignCertificate">Key Usage must have Digital Signature (80)</param>
/// <param name="NeedPrivateKey">The Cerificate must have a private key.</param>
/// <param name="AllowCertificateSelfSigned">Relax checks if it is a self signed certificate.</param>
/// <param name="RevocationFlag">RevocationFlag</param>
/// <param name="RevocationMode">RevocationMode</param>
/// <param name="VerificationFlags">VerificationFlags</param>
/// <param name="ValidateValidityPeriod">Validate NotBefore and NotAfter</param>
/// <param name="TrustMode">The mode determining the root trust for building the certificate chain.</param>
/// <param name="CustomTrustStore">Represents a collection of certificates replacing the default certificate trust.</param>
/// <param name="AdditionalChainCertificates">AdditionalChainCertificates</param>
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
