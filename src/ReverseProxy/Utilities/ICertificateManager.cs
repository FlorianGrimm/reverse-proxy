using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public interface ICertificateManager
{
#if false
    CertificateRequestCollection AddConfiguration(string id, CertificateConfig? certificateConfig, List<CertificateConfig>? certificateConfigs, X509Certificate2Collection? x509Certificate2s, CertificateRequirement requirement);
#endif
    CertificateRequest AddRequest(CertificateRequest request);
    void AddRequestCollection(CertificateRequestCollection result);
    IShared<X509Certificate2Collection?> GetCertificateCollection(CertificateRequest request);
    IShared<X509Certificate2Collection?> GetCertificateCollection(CertificateRequestCollection requestCollection);
}
