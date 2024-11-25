using System;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public interface ICertificateVerifier
{
    bool ValidateCertificate(X509Certificate2 certificate, DateTime localNow);
}
