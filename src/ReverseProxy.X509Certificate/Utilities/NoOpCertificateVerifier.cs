using System;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

internal class NoOpCertificateVerifier : ICertificateVerifier
{
    private static ICertificateVerifier? _instance;

    internal static ICertificateVerifier GetInstance()
        => _instance ??= new NoOpCertificateVerifier();

    public bool ValidateCertificate(X509Certificate2 certificate, System.DateTime localNow)
        => true;
}
