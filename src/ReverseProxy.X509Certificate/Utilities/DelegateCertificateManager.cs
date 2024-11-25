using System;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// A <see cref="ICertificateManager"/> that delegates the loading to a func.
/// </summary>
public class DelegateCertificateManager : ICertificateManager
{
    private readonly Func<string, X509Certificate2Collection?> _getCertificate;

    /// <summary>
    /// Delegates the loading to an func-callback.
    /// </summary>
    /// <param name="getCertificate">the func that creates the certificate</param>
    public DelegateCertificateManager(
        Func<string /*certificateId*/, X509Certificate2Collection?> getCertificate
        )
    {
        _getCertificate = getCertificate;
    }
    public ISharedValue<X509Certificate2Collection?> GetCertificateCollection(string certificateId)
    {
        var certificates = _getCertificate(certificateId);
        return new SharedValue(certificates);
    }

    internal class SharedValue : ISharedValue<X509Certificate2Collection?>
    {
        public SharedValue(X509Certificate2Collection? value)
        {
            Value = value;
        }

        public X509Certificate2Collection? Value { get; private set; }

        public X509Certificate2Collection? GiveAway()
        {
            var result = Value;
            Value = default;
            return result;
        }

        public void Dispose()
        {
            var value = Value;
            Value = null;
            value.DisposeCertificatesExcept();
        }
    }
}

