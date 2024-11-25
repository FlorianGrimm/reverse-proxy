using System;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy.Utilities;

public class CertificateLoaderStore : ICertificateLoader
{
    private readonly ILogger<CertificateLoaderStore> _logger;
    private ICertificateVerifier _certificateVerifier;

    public CertificateLoaderStore(
        ILogger<CertificateLoaderStore> logger
        )
    {
        _logger = logger;
        _certificateVerifier = NoOpCertificateVerifier.GetInstance();

    }

    public void SetOptions(CertificateManagerOptions options) { }

    public void SetCertificateVerifier(ICertificateVerifier certificateVerifier)
    {
        _certificateVerifier = certificateVerifier;
    }


    public LoadCertificateResponse LoadCertificate(CertificateConfiguration certificateConfiguration, System.DateTime localNow)
    {
        if (!certificateConfiguration.IsStoreCertificate()) { return new(false, default); }

        try
        {
            using (var store = new X509Store(certificateConfiguration.StoreName, certificateConfiguration.StoreLocation))
            {
                X509Certificate2Collection? storeCertificates = null;
                try
                {
                    store.Open(OpenFlags.ReadOnly);
                    storeCertificates = store.Certificates;

                    {
                        var foundBySubjectDistinguishedName = storeCertificates.Find(X509FindType.FindBySubjectDistinguishedName, certificateConfiguration.Subject, false);
                        if (0 < foundBySubjectDistinguishedName.Count)
                        {
                            foundBySubjectDistinguishedName.ValidateCertificate(_certificateVerifier, localNow);
                            Log.SuccessfullyLoadedCertificateBySubject(_logger, foundBySubjectDistinguishedName.Count, certificateConfiguration.Subject);
                            storeCertificates.DisposeCertificatesExceptCollection(foundBySubjectDistinguishedName);
                            storeCertificates = null;
                            return new(true, foundBySubjectDistinguishedName);
                        }
                    }

                    {
                        var foundBySubjectName = storeCertificates.Find(X509FindType.FindBySubjectName, certificateConfiguration.Subject, false);
                        if (0 < foundBySubjectName.Count)
                        {
                            foundBySubjectName.ValidateCertificate(_certificateVerifier, localNow);
                            storeCertificates.DisposeCertificatesExceptCollection(foundBySubjectName);
                            storeCertificates = null;
                            Log.SuccessfullyLoadedCertificateBySubject(_logger, foundBySubjectName.Count, certificateConfiguration.Subject);
                            return new(true, foundBySubjectName);
                        }
                    }
                }
                finally
                {
                    storeCertificates.DisposeCertificatesExcept(null);
                }
            }
            _logger.LogDebug("No Certificate with Subject {Subject} found.", certificateConfiguration.Subject);
            return new(false, default);
        }
        catch
        {
            _logger.LogDebug("No Certificate with Subject {Subject} found.", certificateConfiguration.Subject);
            return new(false, default);
        }
    }

    private static class Log
    {
        private static readonly Action<ILogger, int, string, Exception?> _successfullyLoadedCertificateBySubject = LoggerMessage.Define<int, string>(
            LogLevel.Debug,
            EventIds.SuccessfullyLoadedCertificateBySubject,
            "#{Count} Certificates found with Subject {Subject}.");

        public static void SuccessfullyLoadedCertificateBySubject(ILogger logger, int count, string subject)
        {
            _successfullyLoadedCertificateBySubject(logger, count, subject, null);
        }

        private static readonly Action<ILogger, string, Exception?> _noCertificateFoundBySubject = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.NoCertificateFoundBySubject,
            "No Certificate with Subject {Subject} found.");

        public static void NoCertificateFoundBySubject(ILogger logger, string subject)
        {
            _noCertificateFoundBySubject(logger, subject, null);
        }
    }
}
