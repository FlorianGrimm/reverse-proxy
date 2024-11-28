using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Components.Web;
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
        if (string.IsNullOrEmpty(that.CertificateRoot))
        {
            that.CertificateRoot = System.AppContext.BaseDirectory;
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

        if (System.Enum.TryParse<X509RevocationMode>(configuration.GetSection(nameof(CertificateManagerOptions.RevocationMode)).Value, out var valueRevocationMode))
        {
            that.RevocationMode = valueRevocationMode;
        }

        if (System.Enum.TryParse<X509VerificationFlags>(configuration.GetSection(nameof(CertificateManagerOptions.VerificationFlags)).Value, out var valueVerificationFlags))
        {
            that.VerificationFlags = valueVerificationFlags;
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
        if (System.Enum.TryParse<StoreLocation>(configuration.GetSection(nameof(CertificateConfiguration.StoreLocation)).Value, out var valueStoreLocation))
        {
            that.StoreLocation = valueStoreLocation;
        }
        if (System.Enum.TryParse<StoreName>(configuration.GetSection(nameof(CertificateConfiguration.StoreName)).Value, out var valueStoreName))
        {
            that.StoreName = valueStoreName;
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
}
