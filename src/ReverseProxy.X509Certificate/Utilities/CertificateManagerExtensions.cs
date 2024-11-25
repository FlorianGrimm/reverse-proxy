using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public static class CertificateManagerExtensions
{
    public static bool IsFileCertificate(this CertificateConfiguration that)
        => that.Path is { Length: > 0 };

    public static bool IsStoreCertificate(this CertificateConfiguration that)
        => that.Subject is { Length: > 0 };

    public static void Bind(
        this CertificateManagerOptions that,
        IConfiguration configuration)
    {

        if (configuration.GetSection(nameof(CertificateManagerOptions.CertificateRoot)).Value is { Length: > 0 } valueCertificateRoot)
        {
            that.CertificateRoot = valueCertificateRoot;
        }
        if (bool.TryParse(configuration.GetSection(nameof(CertificateManagerOptions.AllowSelfSigned)).Value, out var valueAllowSelfSigned))
        {
            that.AllowSelfSigned = valueAllowSelfSigned;
        }

        foreach (var cfgCertificatesChild in configuration.GetSection(nameof(CertificateManagerOptions.Certificates)).GetChildren())
        {
            var listCertificateConfiguration = (new ListCertificateConfiguration()).Bind(cfgCertificatesChild);
            that.Certificates.Add(cfgCertificatesChild.Key, listCertificateConfiguration);
        }
    }

    public static ListCertificateConfiguration Bind(
        this ListCertificateConfiguration that,
        IConfiguration configuration)
    {
        foreach (var cfgCertificate in configuration.GetChildren())
        {
            var certificateConfiguration = (new CertificateConfiguration()).Bind(cfgCertificate);
            that.Items.Add(certificateConfiguration);
        }
        return that;
    }
    public static CertificateConfiguration Bind(
        this CertificateConfiguration that,
        IConfiguration configuration)
    {
        if (configuration.GetSection(nameof(CertificateConfiguration.StoreLocation)).Value is { Length: > 0 } valueStoreLocation)
        {
            that.StoreLocation = ConvertStoreLocation(valueStoreLocation);
        }
        if (configuration.GetSection(nameof(CertificateConfiguration.StoreName)).Value is { Length: > 0 } valueStoreName)
        {
            that.StoreName = ConvertStoreName(valueStoreName);
        }
        if (configuration.GetSection(nameof(CertificateConfiguration.Subject)).Value is { Length: > 0 } valueSubject)
        {
            that.Subject = valueSubject;
        }

        if (configuration.GetSection(nameof(CertificateConfiguration.Path)).Value is { Length: > 0 } valuePath)
        {
            that.Path = valuePath;
        }
        if (configuration.GetSection(nameof(CertificateConfiguration.KeyPath)).Value is { Length: > 0 } valueKeyPath)
        {
            that.KeyPath = valueKeyPath;
        }
        if (configuration.GetSection(nameof(CertificateConfiguration.Password)).Value is { Length: > 0 } valuePassword)
        {
            that.Password = valuePassword;
        }

        return that;
    }

    private static StoreLocation ConvertStoreLocation(string? valueStoreLocation)
        => ((valueStoreLocation ?? string.Empty).ToLowerInvariant()) switch
        {
            "localmachine" => StoreLocation.LocalMachine,
            _ => StoreLocation.CurrentUser
        };

    private static StoreName ConvertStoreName(string? valueStoreName)
        => ((valueStoreName ?? string.Empty).ToLowerInvariant()) switch
        {
            "addressbook" => StoreName.AddressBook,
            "authroot" => StoreName.AuthRoot,
            "certificateauthority" => StoreName.CertificateAuthority,
            "disallowed" => StoreName.Disallowed,
            "my" => StoreName.My,
            "root" => StoreName.Root,
            "trustedpeople" => StoreName.TrustedPeople,
            "trustedpublisher" => StoreName.TrustedPublisher,
            _ => StoreName.My
        };
}
