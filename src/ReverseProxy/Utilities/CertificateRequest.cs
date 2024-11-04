using System.Diagnostics.CodeAnalysis;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// This class is used to load/find a certificate.
/// Where to get the certificate from, which property to use, how to validate it.
/// </summary>
public record struct CertificateRequest(
    string Id,
    CertificateConfig? CertificateConfig,
    CertificateStoreRequest? StoreRequest,
    CertificateFileRequest? FileRequest,
    CertificateRequirement? Requirement
    )
{

    /*
    */
    public CertificateRequest(
        string Id,
        CertificateConfig certificateConfig,
        CertificateRequirement requirement
        ) : this(
                Id: Id,
                CertificateConfig: certificateConfig,
                StoreRequest: CertificateStoreRequest.Convert(
                    storeLocationName: CertificateStoreLocationName.Convert(certificateConfig.StoreLocation, certificateConfig.StoreName),
                    subject: certificateConfig.Subject
                    ),
                FileRequest: CertificateFileRequest.Convert(
                    path: certificateConfig.Path,
                    keyPath: certificateConfig.KeyPath,
                    password: certificateConfig.Password
                    ),
                Requirement: requirement
            )
    {
    }

    // Cert store

    [MemberNotNullWhen(true, nameof(StoreRequest))]
    public readonly bool IsStoreCert() => (StoreRequest is { } storeRequest) && storeRequest.IsValid();

    // File

    [MemberNotNullWhen(true, nameof(FileRequest))]
    public readonly bool IsFileCert() => (FileRequest is { } fileRequest) && fileRequest.IsValid();
}
