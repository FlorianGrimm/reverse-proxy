using Microsoft.Extensions.Configuration;

using Xunit;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

public class AuthorizationTransportOptionsTests
{
    [Fact]
    public void BindAllTest()
    {
        var optionsExpected = new AuthorizationTransportOptions();
        optionsExpected.EnableForAllCluster = true;
        optionsExpected.DoNotModifyAuthorizationIfBearer = true;
        optionsExpected.RemoveHeaderAuthenticate = true;
        optionsExpected.Scheme = nameof(optionsExpected.Scheme);
        optionsExpected.ExcludeClaimType.Add("1");
        optionsExpected.ExcludeClaimType.Add("2");
        optionsExpected.TransformClaimType.Add("3", "A");
        optionsExpected.TransformClaimType.Add("4", "B");
        optionsExpected.IncludeClaimType.Add("5");
        optionsExpected.IncludeClaimType.Add("6");
        optionsExpected.Issuer = nameof(optionsExpected.Issuer);
        optionsExpected.Audience = nameof(optionsExpected.Audience);
        optionsExpected.AuthenticationType = nameof(optionsExpected.AuthenticationType);
        optionsExpected.AdjustNotBefore = System.TimeSpan.FromMinutes(12);
        optionsExpected.AdjustExpires = System.TimeSpan.FromMinutes(34);
        optionsExpected.SigningCertificateConfig = new CertificateConfig()
        {
            Path = nameof(CertificateConfig.Path),
            KeyPath = nameof(CertificateConfig.KeyPath),
            Password = nameof(CertificateConfig.Password),
            Subject = nameof(CertificateConfig.Subject),
            StoreName = nameof(CertificateConfig.StoreName),
            StoreLocation = nameof(CertificateConfig.StoreLocation),
            AllowInvalid = true
        };
        optionsExpected.Algorithm = nameof(optionsExpected.Algorithm);
        var jsonOptionsExpected = System.Text.Json.JsonSerializer.Serialize(optionsExpected);

        Microsoft.Extensions.Configuration.ConfigurationBuilder configurationBuilder = new();
        configurationBuilder.AddJsonStream(new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(jsonOptionsExpected)));
        var configuration = configurationBuilder.Build();

        var optionsActual = new AuthorizationTransportOptions();
        optionsActual.Bind(configuration);

        Assert.Equal(optionsExpected.EnableForAllCluster, optionsActual.EnableForAllCluster);
        Assert.Equal(optionsExpected.DoNotModifyAuthorizationIfBearer, optionsActual.DoNotModifyAuthorizationIfBearer);
        Assert.Equal(optionsExpected.RemoveHeaderAuthenticate, optionsActual.RemoveHeaderAuthenticate);
        Assert.Equal(optionsExpected.Scheme, optionsActual.Scheme);
        Assert.Equal(optionsExpected.ExcludeClaimType, optionsActual.ExcludeClaimType);
        Assert.Equal(optionsExpected.ExcludeClaimType, optionsActual.ExcludeClaimType);
        Assert.Equal(optionsExpected.TransformClaimType, optionsActual.TransformClaimType);
        Assert.Equal(optionsExpected.IncludeClaimType, optionsActual.IncludeClaimType);
        Assert.Equal(optionsExpected.Issuer, optionsActual.Issuer);
        Assert.Equal(optionsExpected.Audience, optionsActual.Audience);
        Assert.Equal(optionsExpected.AuthenticationType, optionsActual.AuthenticationType);
        Assert.Equal(optionsExpected.AdjustNotBefore, optionsActual.AdjustNotBefore);
        Assert.Equal(optionsExpected.AdjustExpires, optionsActual.AdjustExpires);
        Assert.Equal(optionsExpected.SigningCertificateConfig.Path, optionsActual.SigningCertificateConfig.Path);
        Assert.Equal(optionsExpected.SigningCertificateConfig.KeyPath, optionsActual.SigningCertificateConfig.KeyPath);
        Assert.Equal(optionsExpected.SigningCertificateConfig.Password, optionsActual.SigningCertificateConfig.Password);
        Assert.Equal(optionsExpected.SigningCertificateConfig.Subject, optionsActual.SigningCertificateConfig.Subject);
        Assert.Equal(optionsExpected.SigningCertificateConfig.StoreName, optionsActual.SigningCertificateConfig.StoreName);
        Assert.Equal(optionsExpected.SigningCertificateConfig.StoreLocation, optionsActual.SigningCertificateConfig.StoreLocation);
        Assert.Equal(optionsExpected.SigningCertificateConfig.AllowInvalid, optionsActual.SigningCertificateConfig.AllowInvalid);
        Assert.Equal(optionsExpected.Algorithm, optionsActual.Algorithm);

        var jsonOptionsActual = System.Text.Json.JsonSerializer.Serialize(optionsActual);
        Assert.Equal(jsonOptionsExpected, jsonOptionsActual);
    }

    [Fact]
    public void BindEmptyTest()
    {
        var optionsExpected = new AuthorizationTransportOptions();
        var jsonOptionsExpected = System.Text.Json.JsonSerializer.Serialize(optionsExpected);

        Microsoft.Extensions.Configuration.ConfigurationBuilder configurationBuilder = new();
        configurationBuilder.AddJsonStream(new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(jsonOptionsExpected)));
        var configuration = configurationBuilder.Build();

        var optionsActual = new AuthorizationTransportOptions();
        optionsActual.Bind(configuration);

        var jsonOptionsActual = System.Text.Json.JsonSerializer.Serialize(optionsActual);
        Assert.Equal(jsonOptionsExpected, jsonOptionsActual);
    }
}
