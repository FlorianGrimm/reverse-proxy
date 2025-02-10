using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Authentication;
internal class TransportJwtBearerTokenSigningCertificate
{
    private readonly ICertificateManager _certificateManager;
    private TransportJwtBearerTokenOptions _options;

    public TransportJwtBearerTokenSigningCertificate(
        ICertificateManager certificateManager,
        IOptionsMonitor<TransportJwtBearerTokenOptions> options)
    {
        _certificateManager = certificateManager;
        _options = options.CurrentValue;
        options.OnChange(OptionsOnChange);
    }

    private void OptionsOnChange(TransportJwtBearerTokenOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }

        _options = options;
    }

    internal ISharedValue<SecurityKey?>? GetIssuerSigningKey()
    {
        // TODO: Implement this method
        throw new NotImplementedException();
    }
    internal ISharedValue<SigningCredentials?>? GetSigningCredentials()
    {
        if (_options.CreateSigningCredential is { })
        {
            var signingCredentials = _options.CreateSigningCredential();
            if (signingCredentials is { })
            {
                return new ImmutableSharedValue<SigningCredentials>(signingCredentials);
            }
        }

        {
            var symmetricSigningCredentials = GetSymmetricSigningCredentials();
            if (symmetricSigningCredentials is { })
            {
                return symmetricSigningCredentials;
            }
        }

        {
            var x509CertificateSigningCredentials = GetX509CertificateSigningCredentials();
            if (x509CertificateSigningCredentials is { })
            {
                return x509CertificateSigningCredentials;
            }
        }
        return null;
    }

    internal ISharedValue<SigningCredentials?>? GetSymmetricSigningCredentials()
    {
        if (!(_options.SigningKeySecret is { Length: > 0 } signingKeySecret)) { return null; }

        var bytesSigningKeySecret = Encoding.UTF8.GetBytes(signingKeySecret);
        var securityKey = new SymmetricSecurityKey(bytesSigningKeySecret);

        string algorithm;
        if (securityKey.IsSupportedAlgorithm(_options.Algorithm))
        {
            algorithm = _options.Algorithm;
        }
        else
        {
            algorithm = SecurityAlgorithms.HmacSha256Signature;
        }
        var signingCredentials = new SigningCredentials(securityKey, algorithm);
        return new ImmutableSharedValue<SigningCredentials>(signingCredentials);
    }

    internal ISharedValue<SigningCredentials?>? GetX509CertificateSigningCredentials()
    {
        if (!(_options.SigningCertificate is { Length: > 0 } signingCertificate)) { return null; }

        var certificateCollection = _certificateManager.GetCertificateCollection(signingCertificate);
        if (!(certificateCollection is { Value.Count: > 0 })) { return null; }

        var signingCertificate2 = certificateCollection.Value[0];
        X509SecurityKey securityKey = new(signingCertificate2);
        var signingCredentials = new SigningCredentials(securityKey, _options.Algorithm);
        return new ImmutableSharedValue<SigningCredentials>(signingCredentials);
    }
}
