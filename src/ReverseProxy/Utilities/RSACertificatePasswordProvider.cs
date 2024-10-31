using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;

public class RSACertificatePasswordOptions
{
    public RSAEncryptionPadding RSAEncryptionPadding { get; set; } = RSAEncryptionPadding.OaepSHA256;
    public X509Certificate2? Certificate { get; set; }
}

public class RSACertificatePasswordProvider
    : ICertificatePasswordProvider
    , IDisposable
{
    private IDisposable? _unwireOptionsOnChange;

    public RSAEncryptionPadding RSAEncryptionPadding { get; set; } = RSAEncryptionPadding.OaepSHA256;

    public static RSACertificatePasswordProvider Create(
        X509Certificate2 certificate,
        RSAEncryptionPadding rsaEncryptionPadding
        ) => new RSACertificatePasswordProvider(certificate, rsaEncryptionPadding);

    protected RSACertificatePasswordProvider(
        X509Certificate2 certificate,
        RSAEncryptionPadding rsaEncryptionPadding)
    {
        Certificate = certificate;
        RSAEncryptionPadding = rsaEncryptionPadding;
    }

    public RSACertificatePasswordProvider(
        IOptionsMonitor<RSACertificatePasswordOptions> options
        )
    {
        _unwireOptionsOnChange = options.OnChange(optionsOnChange);
        optionsOnChange(options.CurrentValue, name: null);
    }

    private void optionsOnChange(RSACertificatePasswordOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }

        if (options.Certificate is { } certificate)
        {
            Certificate = certificate;
        }
        RSAEncryptionPadding = options.RSAEncryptionPadding;
    }

    public X509Certificate2? Certificate { get; set; }

    public string DecryptPassword(string value)
    {
        if (Certificate is not { } certificate)
        {
            throw new InvalidOperationException("No Certificate");
        }

        using (var rsa = certificate.GetRSAPrivateKey())
        {
            if (rsa == null)
            {
                throw new InvalidOperationException("The certificate does not have a private key.");
            }
            var bytes = System.Convert.FromBase64String(value);
            var result = rsa.Decrypt(bytes, RSAEncryptionPadding);
            return System.Text.Encoding.UTF8.GetString(result);
        }
    }

    public string EncryptPassword(string value)
    {
        if (Certificate is not { } certificate)
        {
            throw new InvalidOperationException("No Certificate");
        }

        using (var rsa = certificate.GetRSAPublicKey())
        {
            if (rsa == null)
            {
                throw new InvalidOperationException("The certificate does not have a public key.");
            }
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            rsa.Encrypt(bytes, RSAEncryptionPadding);
            return System.Convert.ToBase64String(bytes);
        }
    }

    public void Dispose()
    {
        using (var unwireOptionsOnChange = _unwireOptionsOnChange)
        {
            _unwireOptionsOnChange = null;
        }
    }
}
