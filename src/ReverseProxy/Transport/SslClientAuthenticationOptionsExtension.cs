using System.Security.Cryptography.X509Certificates;

namespace System.Net.Security;

public static class SslClientAuthenticationOptionsExtension
{
    public static void AddClientCertificate(this SslClientAuthenticationOptions sslOptions, params X509Certificate[] value)
    {
        (sslOptions.ClientCertificates ??= new()).AddRange(value);
        sslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
        if (value.Length > 0)
        {
            var cert = value[0];
            sslOptions.LocalCertificateSelectionCallback = (sender, host, localCertificates, remoteCertificate, acceptableIssuers) =>
            {
                return cert;
            };
        }
    }
}
