using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Represents a class that handles the loading of certificates from files.
/// </summary>
public interface ICertificateFileLoader
{
    string? CertificateRootPath { get; set; }

    X509Certificate2Collection? LoadCertificateFromFile(
        List<CertificateRequest> requests,
        CertificateFileRequest fileRequest,
        CertificateRequirement requirement);

    X509Certificate2Collection? LoadCertificateFromFile(
        CertificateRequest requests,
        CertificateFileRequest fileRequest,
        CertificateRequirement requirement);
}

/// <summary>
/// Parameter for loading certificates from files.
/// </summary>
/// <param name="Path">The path to and certificate file. (cer, pem, pfx,..)</param>
/// <param name="KeyPath">The path to the private key certificate.</param>
/// <param name="Password">The (encrypted) password <see cref="ICertificatePasswordProvider"/> </param>
public record struct CertificateFileRequest(
    string? Path,
    string? KeyPath,
    string? Password
    )
{
    /// <summary>
    /// Converts the parameters to a <see cref="CertificateFileRequest"/>.
    /// </summary>
    /// <param name="path">The path to and certificate file. (cer, pem, pfx,..)</param>
    /// <param name="keyPath">The path to the private key certificate.</param>
    /// <param name="password">The (encrypted) password <see cref="ICertificatePasswordProvider"/> </param>
    /// <returns>null if path is empty otherwise a new instance.</returns>
    public static CertificateFileRequest? Convert(
        string? path,
        string? keyPath,
        string? password
        )
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        return new CertificateFileRequest(path, keyPath, password);
    }

    /// <summary>
    /// Checks if the path is not empty.
    /// </summary>
    /// <returns>true if the path is not empty.</returns>
    [MemberNotNullWhen(true, nameof(Path))]
    public bool IsValid() =>
        !string.IsNullOrEmpty(Path);
}
