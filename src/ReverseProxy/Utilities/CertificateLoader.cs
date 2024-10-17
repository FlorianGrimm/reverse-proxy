// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

// based on https://github.com/dotnet/aspnetcore.git src\Servers\Kestrel\Core\src\Internal\Certificates\CertificateConfigLoader.cs

public interface ICertificateLoader
{
    (X509Certificate2?, X509Certificate2Collection?) LoadCertificateNoPrivateKey(CertificateConfig? certInfo, string name);
    (X509Certificate2?, X509Certificate2Collection?) LoadCertificateWithPrivateKey(CertificateConfig? certInfo, string name);
}

public sealed partial class CertificateLoader : ICertificateLoader
{
    private readonly ILogger<CertificateLoader> _logger;
    private readonly string _certificateRoot;
    private readonly Func<CertificateConfig, string?> _getCertificatePassword;

    public CertificateLoader(
        IOptions<CertificateLoaderOptions> options,
        IHostEnvironment hostEnvironment,
        ILogger<CertificateLoader> logger)
    {
        _logger = logger;
        var optionsValue = options.Value;

        _certificateRoot =  optionsValue.CertificateRoot is { Length:>0 } certificateRoot ? certificateRoot : hostEnvironment.ContentRootPath;
        _getCertificatePassword = optionsValue.GetCertificatePassword;
    }

    public (X509Certificate2?, X509Certificate2Collection?) LoadCertificateNoPrivateKey(CertificateConfig? certInfo, string name)
    {
        if (certInfo is null)
        {
            return (null, null);
        }

        if (certInfo.IsFileCert() && certInfo.IsStoreCert())
        {
            throw new InvalidOperationException($"Multiple CertificateSources ({name})");
        }
        else if (certInfo.IsFileCert() && certInfo.Path is { Length: > 0 } certInfoPath)
        {
            var certificatePath = Path.Combine(_certificateRoot, certInfoPath);
            if (!File.Exists(certificatePath))
            {
                Log.FailedToLoadCertificate(_logger, certificatePath);
                return (null, null);
            }
            var fullChain = new X509Certificate2Collection();
            fullChain.ImportFromPemFile(certificatePath);

            var password = _getCertificatePassword(certInfo);
            return (new X509Certificate2(certificatePath, password), fullChain);
        }
        else if (certInfo.IsStoreCert())
        {
            return (LoadFromStoreCert(certInfo, false), null);
        }

        return (null, null);
    }


    public (X509Certificate2?, X509Certificate2Collection?) LoadCertificateWithPrivateKey(CertificateConfig? certInfo, string name)
    {
        if (certInfo is null)
        {
            return (null, null);
        }

        if (certInfo.IsFileCert() && certInfo.IsStoreCert())
        {
            throw new InvalidOperationException($"Multiple CertificateSources ({name})");
        }
        else if (certInfo.IsFileCert() && certInfo.Path is { Length: > 0 } certInfoPath)
        {
            var certificatePath = Path.Combine(_certificateRoot, certInfoPath);
            if (!File.Exists(certificatePath))
            {
                Log.FailedToLoadCertificate(_logger, certificatePath);
                return (null, null);
            }
            var fullChain = new X509Certificate2Collection();
            fullChain.ImportFromPemFile(certificatePath);


            if (certInfo.KeyPath is { Length: > 0 })
            {
                var certificateKeyPath = Path.Combine(_certificateRoot, certInfo.KeyPath);
                var certificate = GetCertificate(certificatePath);

                if (certificate != null)
                {
                    if (!File.Exists(certificateKeyPath))
                    {
                        Log.FailedToLoadCertificateKey(_logger, certificateKeyPath);
                    }
                    else
                    {
                        var password = _getCertificatePassword(certInfo);
                        certificate = LoadCertificateKey(certificate, certificateKeyPath, password);
                    }
                }
                else
                {
                    Log.FailedToLoadCertificate(_logger, certificateKeyPath);
                }

                if (certificate != null)
                {
                    if (OperatingSystem.IsWindows())
                    {
                        Log.SuccessfullyLoadedCertificateKey(_logger, certificateKeyPath);
                        return (PersistKey(certificate), fullChain);
                    }
                    else {
                        Log.SuccessfullyLoadedCertificateKey(_logger, certificateKeyPath);
                        return (certificate, fullChain);
                    }
                }

                Log.FailedToLoadCertificateKey(_logger, certificateKeyPath);
                throw new InvalidOperationException("The provided key file is missing or invalid.");
            }

            // fallback
            {
                var password = _getCertificatePassword(certInfo);
                var certificate = new X509Certificate2(certificatePath, password);
                Log.SuccessfullyLoadedCertificateKey(_logger, certificatePath);
                return (certificate, fullChain);
            }
        }
        else if (certInfo.IsStoreCert())
        {
            return (LoadFromStoreCert(certInfo, true), null);
        }

        return (null, null);
    }

    private static X509Certificate2 PersistKey(X509Certificate2 fullCertificate)
    {
        // We need to force the key to be persisted.
        // See https://github.com/dotnet/runtime/issues/23749
        var certificateBytes = fullCertificate.Export(X509ContentType.Pkcs12, "");
        return new X509Certificate2(certificateBytes, "", X509KeyStorageFlags.DefaultKeySet);
    }

    private static X509Certificate2 LoadCertificateKey(X509Certificate2 certificate, string keyPath, string? password)
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

    private static InvalidOperationException CreateErrorGettingPrivateKeyException(string keyPath, Exception ex)
    {
        return new InvalidOperationException($"Error getting private key from '{keyPath}'.", ex);
    }

    private static X509Certificate2? GetCertificate(string certificatePath)
    {
        if (X509Certificate2.GetCertContentType(certificatePath) == X509ContentType.Cert)
        {
            return new X509Certificate2(certificatePath);
        }

        return null;
    }

    private static void ImportKeyFromFile(AsymmetricAlgorithm asymmetricAlgorithm, string keyText, string? password)
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

    private static X509Certificate2 LoadFromStoreCert(CertificateConfig certInfo, bool needPrivateKey)
    {
        var subject = certInfo.Subject!;
        var storeName = string.IsNullOrEmpty(certInfo.Store) ? StoreName.My.ToString() : certInfo.Store;
        var location = certInfo.Location;
        var storeLocation = StoreLocation.CurrentUser;
        if (!string.IsNullOrEmpty(location))
        {
            storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), location, ignoreCase: true);
        }
        var allowInvalid = certInfo.AllowInvalid ?? false;

        return ClientCertificateLoader.LoadFromStoreCert(subject, storeName, storeLocation, allowInvalid, needPrivateKey);
    }

    internal static class Log
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
