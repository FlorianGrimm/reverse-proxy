using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public record struct CertificateRequirement(
    bool ClientCertificate,
    bool SignCertificate,
    bool NeedPrivateKey,

    X509RevocationFlag? RevocationFlag,
    X509RevocationMode? RevocationMode,
    X509VerificationFlags? VerificationFlags
    );
