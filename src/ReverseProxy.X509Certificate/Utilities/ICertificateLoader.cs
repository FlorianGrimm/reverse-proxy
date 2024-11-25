using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public interface ICertificateLoader
{
    void SetOptions(CertificateManagerOptions options);

    void SetCertificateVerifier(ICertificateVerifier certificateVerifier);

    LoadCertificateResponse LoadCertificate(CertificateConfiguration certificateConfiguration, System.DateTime localNow);
}

public record struct LoadCertificateResponse(
    bool MatchedLoader,
    X509Certificate2Collection? Collection
    );
