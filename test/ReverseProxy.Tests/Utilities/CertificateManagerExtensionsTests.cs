using System.Security.Cryptography.X509Certificates;

using Xunit;

namespace Yarp.ReverseProxy.Utilities;

public class CertificateManagerExtensionsTests
{
    [Fact]
    public void Combine_ClientCertificate()
    {
        {
            var a = new CertificateRequirement();
            var b = new CertificateRequirement();
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.False(result.ClientCertificate);
        }
        {
            var a = new CertificateRequirement();
            var b = new CertificateRequirement()
            {
                ClientCertificate = true,
            };
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.ClientCertificate);
            Assert.True(result.NeedPrivateKey);
        }
        {
            var a = new CertificateRequirement() {
                ClientCertificate = true,
            };
            var b = new CertificateRequirement();
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.ClientCertificate);
            Assert.True(result.NeedPrivateKey);
        }
    }

    [Fact]
    public void Combine_SignCertificate()
    {
        {
            var a = new CertificateRequirement();
            var b = new CertificateRequirement();
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.False(result.SignCertificate);
        }
        {
            var a = new CertificateRequirement();
            var b = new CertificateRequirement()
            {
                SignCertificate = true,
            };
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.SignCertificate);
            Assert.False(result.NeedPrivateKey);
        }
        {
            var a = new CertificateRequirement()
            {
                SignCertificate = true,
            };
            var b = new CertificateRequirement();
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.SignCertificate);
            Assert.False(result.NeedPrivateKey);
        }
    }

    [Fact]
    public void Combine_RevocationFlag_NoValue()
    {
        {
            var a = new CertificateRequirement();
            var b = new CertificateRequirement();
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.False(result.RevocationFlag.HasValue);
        }
    }

    [Fact]
    public void Combine_RevocationFlag_OneValue()
    {

        {
            var a = new CertificateRequirement();
            var b = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.EntireChain,
            };
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.RevocationFlag.HasValue);
            Assert.Equal(X509RevocationFlag.EntireChain, result.RevocationFlag.Value);
        }
        {
            var a = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.EntireChain,
            };
            var b = new CertificateRequirement();
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.RevocationFlag.HasValue);
            Assert.Equal(X509RevocationFlag.EntireChain, result.RevocationFlag.Value);
        }
    }

    [Fact]
    public void Combine_RevocationFlag_ToStrong()
    {
        {
            var a = new CertificateRequirement() {
                RevocationFlag = X509RevocationFlag.EndCertificateOnly,
            };
            var b = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.EndCertificateOnly,
            };
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.RevocationFlag.HasValue);
            Assert.Equal(X509RevocationFlag.EndCertificateOnly, result.RevocationFlag.Value);
        }
        {
            var a = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.EndCertificateOnly,
            };
            var b = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.EntireChain,
            };
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.RevocationFlag.HasValue);
            Assert.Equal(X509RevocationFlag.EntireChain, result.RevocationFlag.Value);
        }
        {
            var a = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.ExcludeRoot,
            };
            var b = new CertificateRequirement()
            {
                RevocationFlag = X509RevocationFlag.EntireChain,
            };
            var result = CertificateManagerExtensions.Combine(a, b);
            Assert.True(result.RevocationFlag.HasValue);
            Assert.Equal(X509RevocationFlag.EntireChain, result.RevocationFlag.Value);
        }
    }

}
