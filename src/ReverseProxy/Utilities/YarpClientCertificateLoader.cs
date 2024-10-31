// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Mvc.Formatters;

namespace Yarp.ReverseProxy.Utilities;

// copied from Microsoft.AspNetCore.Server.Kestrel.Https;

/// <summary>
/// Enables loading client certificates from the certificate store.
/// </summary>
public static class YarpClientCertificateLoader
{
    public static bool IsClientCertificate(string? mode)
        => string.Equals(mode, "ClientCertificate", System.StringComparison.OrdinalIgnoreCase);

    public const string ClientCertificateOid = "1.3.6.1.5.5.7.3.2";


    public static bool IsCertificateAllowedForClientCertificate(X509Certificate2 certificate)
    {
        /* If the Extended Key Usage extension is included, then we check that the serverAuth usage is included. (http://oid-info.com/get/1.3.6.1.5.5.7.3.1)
         * If the Extended Key Usage extension is not included, then we assume the certificate is allowed for all usages.
         *
         * See also https://blogs.msdn.microsoft.com/kaushal/2012/02/17/client-certificates-vs-server-certificates/
         *
         * From https://tools.ietf.org/html/rfc3280#section-4.2.1.13 "Certificate Extensions: Extended Key Usage"
         *
         * If the (Extended Key Usage) extension is present, then the certificate MUST only be used
         * for one of the purposes indicated.  If multiple purposes are
         * indicated the application need not recognize all purposes indicated,
         * as long as the intended purpose is present.  Certificate using
         * applications MAY require that a particular purpose be indicated in
         * order for the certificate to be acceptable to that application.
         */

        var hasEkuExtension = false;

        foreach (var extension in certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>())
        {
            hasEkuExtension = true;
            foreach (var oid in extension.EnhancedKeyUsages)
            {
                if (string.Equals(oid.Value, ClientCertificateOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return !hasEkuExtension;
    }

    public static Func<X509Certificate2, bool> CreateCertificateEnhancedKeyUsageFilter(string keyUsageOid)
    {
        return certificate => IsCertificateAllowedForEnhancedKeyUsage(certificate, keyUsageOid);
    }

    public static bool IsCertificateAllowedForEnhancedKeyUsage(X509Certificate2 certificate, string keyUsageOid)
    {
        var hasEkuExtension = false;

        foreach (var extension in certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>())
        {
            hasEkuExtension = true;
            foreach (var oid in extension.EnhancedKeyUsages)
            {
                if (string.Equals(oid.Value, keyUsageOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return !hasEkuExtension;
    }

    /// <summary>
    /// Loads a certificate from the certificate store.
    /// </summary>
    /// <remarks>
    /// Exact subject match is loaded if present, otherwise best matching certificate with the subject name that contains supplied subject.
    /// Subject comparison is case-insensitive.
    /// </remarks>
    /// <param name="subject">The certificate subject.</param>
    /// <param name="storeName">The certificate store name.</param>
    /// <param name="storeLocation">The certificate store location.</param>
    /// <param name="allowInvalid">Whether or not to load certificates that are considered invalid.</param>
    /// <param name="checkCertifacte"></param>
    /// <param name="needPrivateKey">filter only certificates with private key</param>
    /// <returns>The loaded certificate.</returns>
    public static X509Certificate2 LoadFromStoreCert(
        string subject,
        string storeName,
        StoreLocation storeLocation,
        bool allowInvalid,
        Func<X509Certificate2,bool>? checkCertifacte,
        bool needPrivateKey)
    {
        using (var store = new X509Store(storeName, storeLocation))
        {
            X509Certificate2Collection? storeCertificates = null;
            X509Certificate2? foundCertificate = null;

            try
            {
                store.Open(OpenFlags.ReadOnly);
                storeCertificates = store.Certificates;
                var listFiltered = storeCertificates.Find(X509FindType.FindBySubjectName, subject, !allowInvalid)
                    .OfType<X509Certificate2>()
                    .Where((X509Certificate2 certificate) => {
                        if (needPrivateKey)
                        {
                            if (!DoesCertificateHaveAnAccessiblePrivateKey(certificate))
                            {
                                return false;
                            }
                        }
                        if (checkCertifacte is not null) {
                            if (!checkCertifacte(certificate))
                            {
                                return false;
                            }
                        }
                        return true;
                    })
                    .OrderByDescending(certificate => certificate.NotAfter)
                    ;
                foreach (var certificate in listFiltered)
                {
                    // Pick the first one if there's no exact match as a fallback to substring default.
                    foundCertificate ??= certificate;

                    if (certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false).Equals(subject, StringComparison.InvariantCultureIgnoreCase))
                    {
                        foundCertificate = certificate;
                        break;
                    }
                }

                if (foundCertificate == null)
                {
                    throw new InvalidOperationException($"The requested certificate {subject} could not be found in {storeLocation}/{storeName} with AllowInvalid setting: {allowInvalid}.");
                }

                return foundCertificate;
            }
            finally
            {
                DisposeCertificates(storeCertificates, except: foundCertificate);
            }
        }
    }


#warning TODO: Verify method

    public static bool Verify(X509Certificate2 certificate2, Action<X509ChainPolicy> configure)
    {
        using (var chain = new X509Chain())
        {
            configure(chain.ChainPolicy);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreRootRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown
                | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown;
            /*
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 0);
            */
            // Use the default vales of chain.ChainPolicy including:
            //  RevocationMode = X509RevocationMode.Online
            //  RevocationFlag = X509RevocationFlag.ExcludeRoot
            //  VerificationFlags = X509VerificationFlags.NoFlag
            //  VerificationTime = DateTime.Now
            //  UrlRetrievalTimeout = new TimeSpan(0, 0, 0)

            var verified = chain.Build(certificate2);

            for (var index = 0; index < chain.ChainElements.Count; index++)
            {
                chain.ChainElements[index].Certificate.Dispose();
            }

            return verified;
        }
    }


    public static bool DoesCertificateHaveAnAccessiblePrivateKey(X509Certificate2 certificate)
        => certificate.HasPrivateKey;

    public static void DisposeCertificates(X509CertificateCollection? certificates, X509Certificate? except)
    {
        if (certificates != null)
        {
            foreach (var certificate in certificates)
            {
                if (!certificate.Equals(except))
                {
                    certificate.Dispose();
                }
            }
            certificates.Clear();
        }
    }
}
