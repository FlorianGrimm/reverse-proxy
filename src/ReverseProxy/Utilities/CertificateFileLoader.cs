using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy.Utilities;

public interface ICertificateFileLoader
{
    string? CertificateRootPath { get; set; }
    ICertificateManagerFileWatcher? CertificateManagerFileWatcher { get; set; }

    X509Certificate2Collection? LoadCertificateFromFile(
        List<CertificateRequest> requests,
        CertificateFileRequest fileRequest,
        CertificateRequirement requirement);
}

public record struct CertificateFileRequest(
    string? Path,
    string? KeyPath,
    string? Password
    )
{
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

    [MemberNotNullWhen(true, nameof(Path))]
    public bool IsValid() =>
        !string.IsNullOrEmpty(Path);
}

public class CertificateFileLoader : ICertificateFileLoader
{
    private readonly ICertificatePasswordProvider _certificatePasswordProvider;
    private readonly ILogger _logger;

    public string? CertificateRootPath { get; set; }

    public ICertificateManagerFileWatcher? CertificateManagerFileWatcher { get; set; }

    public CertificateFileLoader(
        ICertificatePasswordProvider certificatePasswordProvider,
        ICertificateManagerFileWatcher? fileWatcher,
        ILogger<CertificateFileLoader> logger)
    {
        _certificatePasswordProvider = certificatePasswordProvider;
        CertificateManagerFileWatcher = fileWatcher;
        _logger = logger;
    }

    public X509Certificate2Collection? LoadCertificateFromFile(
        List<CertificateRequest> requests,
        CertificateFileRequest fileRequest,
        CertificateRequirement requirement
        )
    {
        var (path, keyPath, password) = fileRequest;

        if (string.IsNullOrEmpty(path))
        {
            return null;
        }
        {
            var certificatePath = GetAbsolutePath(path);
            var certificateKeyPath = GetAbsolutePath(keyPath);

            string? plainPassword = null;

            if (string.IsNullOrEmpty(certificatePath))
            {
                return null;
            }
            if (!File.Exists(certificatePath))
            {
                Log.FailedToLoadCertificate(_logger, certificatePath);
                return null;
            }

            var fullChain = new X509Certificate2Collection();

            X509Certificate2? certificate;
            try
            {
                if (plainPassword is null && password is { Length: > 0 })
                {
                    plainPassword = _certificatePasswordProvider.DecryptPassword(password);
                }
                certificate = GetCertificate(certificatePath, plainPassword);
                if (certificate is { })
                {
                    if (OperatingSystem.IsWindows())
                    {
                        Log.SuccessfullyLoadedCertificate(_logger, certificatePath);
                        if (certificate.HasPrivateKey)
                        {
                            certificate = certificate.PersistKey();
                        }
                    }
                    else
                    {
                        Log.SuccessfullyLoadedCertificate(_logger, certificatePath);
                    }
                    fullChain.Add(certificate);

                    // _fileWatcher.AddWatch(certificatePath, certificate);
                }
            }
            catch (CryptographicException)
            {
                certificate = default;
            }

            if (certificate is null)
            {
                try
                {
                    if (plainPassword is null && password is { Length: > 0 })
                    {
                        plainPassword = _certificatePasswordProvider.DecryptPassword(password);
                    }
                    fullChain.Import(certificatePath, plainPassword, X509KeyStorageFlags.DefaultKeySet);
                    if (0 < fullChain.Count)
                    {
                        certificate = fullChain[0];
                        if (certificate is { })
                        {
                            if (OperatingSystem.IsWindows())
                            {
                                if (certificate.HasPrivateKey)
                                {
                                    certificate = certificate.PersistKey();
                                }
                                Log.SuccessfullyLoadedCertificateKey(_logger, certificatePath);
                            }
                            else
                            {
                                Log.SuccessfullyLoadedCertificateKey(_logger, certificatePath);
                            }
                        }
                    }
                }
                catch (CryptographicException)
                {
                }
            }

            if (certificate is null)
            {
                Log.FailedToLoadCertificate(_logger, certificatePath);
                return null;
            }

            if (requirement.NeedPrivateKey && !certificate.HasPrivateKey)
            {
                if (certificateKeyPath is { Length: > 0 })
                {
                    if (!File.Exists(certificateKeyPath))
                    {
                        Log.FailedToLoadCertificateKey(_logger, certificateKeyPath);
                    }
                    else
                    {
                        if (plainPassword is null && password is { Length: > 0 })
                        {
                            plainPassword = _certificatePasswordProvider.DecryptPassword(password);
                        }
                        var certificateKey = LoadCertificateKey(certificate, certificateKeyPath, plainPassword);
                        if (certificateKey != null)
                        {
                            if (OperatingSystem.IsWindows())
                            {
                                certificateKey = certificateKey.PersistKey();
                                Log.SuccessfullyLoadedCertificateKey(_logger, certificateKeyPath);
                            }
                            else
                            {
                                Log.SuccessfullyLoadedCertificateKey(_logger, certificateKeyPath);
                            }

                            var found = false;
                            for (var index = 0; index < fullChain.Count; index++)
                            {
                                if (ReferenceEquals(fullChain[index], certificate))
                                {
                                    fullChain[index] = certificateKey;
                                    found = true;
                                    break;
                                }
                            }
                            if (!found)
                            {
                                fullChain.Add(certificateKey);
                            }
                            return fullChain;
                        }
                    }
                }

                Log.FailedToLoadCertificateKey(_logger, certificatePath);
                throw new InvalidOperationException("The provided key file is missing or invalid.");
            }

            return fullChain;
        }
    }

    private string? GetAbsolutePath(string? path)
    {
        if (CertificateRootPath is { Length: > 0 } certificateRootPath)
        {
            if (path is { Length: > 0 })
            {
                return Path.Combine(certificateRootPath, path);
            }
        }
        return path;
    }

    protected static X509Certificate2 LoadCertificateKey(X509Certificate2 certificate, string keyPath, string? password)
    {
        // OIDs for the certificate key types.
        const string RSAOid = "1.2.840.113549.1.1.1";
        const string DSAOid = "1.2.840.10040.4.1";
        const string ECDsaOid = "1.2.840.10045.2.1";

        // Duplication is required here because there are separate CopyWithPrivateKey methods for each algorithm.
        var keyText = File.ReadAllText(keyPath);
        switch (certificate.PublicKey.Oid.Value)
        {
            case RSAOid:
                {
                    using var rsa = RSA.Create();
                    ImportKeyFromFile(rsa, keyText, password);

                    try
                    {
                        return certificate.CopyWithPrivateKey(rsa);
                    }
                    catch (Exception ex)
                    {
                        throw CreateErrorGettingPrivateKeyException(keyPath, ex);
                    }
                }
            case ECDsaOid:
                {
                    using var ecdsa = ECDsa.Create();
                    ImportKeyFromFile(ecdsa, keyText, password);

                    try
                    {
                        return certificate.CopyWithPrivateKey(ecdsa);
                    }
                    catch (Exception ex)
                    {
                        throw CreateErrorGettingPrivateKeyException(keyPath, ex);
                    }
                }
            case DSAOid:
                {
                    using var dsa = DSA.Create();
                    ImportKeyFromFile(dsa, keyText, password);

                    try
                    {
                        return certificate.CopyWithPrivateKey(dsa);
                    }
                    catch (Exception ex)
                    {
                        throw CreateErrorGettingPrivateKeyException(keyPath, ex);
                    }
                }
            default:
                throw new InvalidOperationException($"Unrecognized Certificate Key Oid {certificate.PublicKey.Oid.Value}");
        }
    }

    protected static InvalidOperationException CreateErrorGettingPrivateKeyException(string keyPath, Exception ex)
    {
        return new InvalidOperationException($"Error getting private key from '{keyPath}'.", ex);
    }

    protected static X509Certificate2? GetCertificate(string certificatePath, string? password)
    {
        var contentType = X509Certificate2.GetCertContentType(certificatePath);
        if ((contentType == X509ContentType.Cert)
            || (contentType == X509ContentType.Pfx)
            || (contentType == X509ContentType.Pkcs7)
            )
        {
            return new X509Certificate2(certificatePath, password);
        }

        return null;
    }

    protected static void ImportKeyFromFile(AsymmetricAlgorithm asymmetricAlgorithm, string keyText, string? password)
    {
        if (password == null)
        {
            asymmetricAlgorithm.ImportFromPem(keyText);
        }
        else
        {
            asymmetricAlgorithm.ImportFromEncryptedPem(keyText, password);
        }
    }

    protected static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _failedToLoadCertificate = LoggerMessage.Define<string>(
            LogLevel.Error,
            EventIds.MissingOrInvalidCertificateFile,
            "The certificate file at '{CertificateFilePath}' can not be found, contains malformed data or does not contain a certificate.");

        public static void FailedToLoadCertificate(ILogger logger, string certificateFilePath, Exception? error = default)
        {
            _failedToLoadCertificate(logger, certificateFilePath, error);
        }

        private static readonly Action<ILogger, string, Exception?> _failedToLoadCertificateKey = LoggerMessage.Define<string>(
            LogLevel.Error,
            EventIds.MissingOrInvalidCertificateKeyFile,
            "The certificate key file at '{CertificateKeyFilePath}' can not be found, contains malformed data or does not contain a PEM encoded key in PKCS8 format.");

        public static void FailedToLoadCertificateKey(ILogger logger, string certificateKeyFilePath, Exception? error = default)
        {
            _failedToLoadCertificateKey(logger, certificateKeyFilePath, error);
        }

        private static readonly Action<ILogger, string, Exception?> _successfullyLoadedCertificate = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.SuccessfullyLoadedCertificate,
            "The certificate key file at '{CertificateKeyFilePath}' was loaded.");

        public static void SuccessfullyLoadedCertificate(ILogger logger, string certificateFilePath, Exception? error = default)
        {
            _successfullyLoadedCertificate(logger, certificateFilePath, error);
        }

        private static readonly Action<ILogger, string, Exception?> _successfullyLoadedCertificateKey = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.SuccessfullyLoadedCertificateKey,
            "The certificate key file at '{CertificateKeyFilePath}' was loaded.");

        public static void SuccessfullyLoadedCertificateKey(ILogger logger, string certificateKeyFilePath, Exception? error = default)
        {
            _successfullyLoadedCertificateKey(logger, certificateKeyFilePath, error);
        }
    }
}

