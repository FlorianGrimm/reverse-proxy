using System.Diagnostics.CodeAnalysis;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// This class is used to load/find a certificate.
/// Where to get the certificate from, which property to use, how to validate it.
/// </summary>
public record struct CertificateRequest(
    CertificateConfig? CertificateConfig,
    CertificateStoreLocationName? StoreLocationName,
    string? Subject,

    string? Path,
    string? KeyPath,
    string? Password,

    CertificateRequirement Requirement
    )
{

    /*
    */
    public CertificateRequest(
        CertificateConfig certificateConfig,
        CertificateRequirement requirement
        ) : this(
                CertificateConfig: certificateConfig,
                StoreLocationName: CertificateStoreLocationName.Convert(certificateConfig.StoreLocation, certificateConfig.StoreName),
                Subject: certificateConfig.Subject,
                Path: certificateConfig.Path,
                KeyPath: certificateConfig.KeyPath,
                Password: certificateConfig.Password,
                Requirement: requirement
            )
    {
    }

    // Cert store

    [MemberNotNullWhen(true, nameof(Subject))]
    [MemberNotNullWhen(true, nameof(StoreLocationName))]
    public readonly bool IsStoreCert() => StoreLocationName.HasValue && !string.IsNullOrEmpty(Subject);

    // File

    [MemberNotNullWhen(true, nameof(Path))]
    public readonly bool IsFileCert() => !string.IsNullOrEmpty(Path);
}
