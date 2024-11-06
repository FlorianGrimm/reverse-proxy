using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public interface ICertificateManager
{
    IDisposable AddRequestCollection(CertificateRequestCollection result);
    ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequestCollection requestCollection);
    ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequest request);
    bool RemoveRequestCollection(CertificateRequestCollection requestCollection);

    /// <summary>
    /// Refresh(reload) the certificates.
    /// </summary>
    /// <param name="force">false - only if needed; true - always</param>
    void Refresh(bool force);
}

public interface ICertificateManagerInternal : ICertificateManager
{
    CertificateRequest AddRequest(CertificateRequest request);
}
