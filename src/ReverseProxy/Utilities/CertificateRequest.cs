using System.Diagnostics.CodeAnalysis;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// This class is used to load/find a certificate.
/// Where to get the certificate from, which property to use, how to validate it.
/// </summary>
/// <param name="Id">The id of this request.</param>
/// <param name="CertificateConfig">The certificate config.</param>
/// <param name="StoreRequest">The request for a store-based certificate..</param>
/// <param name="FileRequest">The request for a file-based certificate.</param>
/// <param name="Requirement">The requirement for this request.</param>
public record struct CertificateRequest(
    string Id,
    CertificateConfig? CertificateConfig,
    CertificateStoreRequest? StoreRequest,
    CertificateFileRequest? FileRequest,
    CertificateRequirement? Requirement
    )
{
    /// <summary>
    /// Converts the parameters to a <see cref="CertificateRequest"/>.
    /// </summary>
    /// <param name="id">The id of this request.</param>
    /// <param name="certificateConfig">The certificate config.</param>
    /// <param name="requirement">The requirement for this request.</param>
    public CertificateRequest(
        string id,
        CertificateConfig certificateConfig,
        CertificateRequirement requirement
        ) : this(
                Id: id,
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
    /// <summary>
    /// Checks if the request is for a store-based certificate.
    /// </summary>
    [MemberNotNullWhen(true, nameof(StoreRequest))]
    public readonly bool IsStoreCert() => (StoreRequest is { } storeRequest) && storeRequest.IsValid();

    /// <summary>
    /// Checks if the request is for a file-based certificate.
    /// </summary>
    [MemberNotNullWhen(true, nameof(FileRequest))]
    public readonly bool IsFileCert() => (FileRequest is { } fileRequest) && fileRequest.IsValid();
}
