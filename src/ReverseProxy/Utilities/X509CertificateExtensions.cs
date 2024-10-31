// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Extension methods for <see cref="X509Certificate2"/>.
/// </summary>
public static class X509Certificate2Extensions
{

    public const string ClientCertificateOid = "1.3.6.1.5.5.7.3.2";


    public static bool IsCertificateAllowedForClientCertificate(this X509Certificate2 certificate)
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
    public static bool IsCertificateAllowedForX509KeyUsageExtension(this X509Certificate2 certificate, X509KeyUsageFlags keyUsage)
    {
        var hasEkuExtension = false;
        
        foreach (var extension in certificate.Extensions.OfType<X509KeyUsageExtension>())
        {
            hasEkuExtension = true;
            if ((extension.KeyUsages & keyUsage) == keyUsage)
            {
                return true;
            }
        }

        return !hasEkuExtension;
    }
    public static bool IsCertificateAllowedForX509EnhancedKeyUsageExtension(this X509Certificate2 certificate, string keyUsageOid)
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
    /// Determines if the certificate is self signed.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <returns>True if the certificate is self signed.</returns>
    public static bool IsSelfSigned2(this X509Certificate2 certificate)
    {

#if NET8_0_OR_GREATER
        Span<byte> subject = certificate.SubjectName.RawData;
        Span<byte> issuer = certificate.IssuerName.RawData;
        return subject.SequenceEqual(issuer);
#else
        var subject = certificate.SubjectName.RawData;
        var issuer = certificate.IssuerName.RawData;
        return subject.SequenceEqual(issuer);
#endif
    }

    public static void DisposeCertificates(
        this X509CertificateCollection? certificateCollection,
        X509Certificate? except)
    {
        if (certificateCollection != null)
        {
            foreach (var certificate in certificateCollection)
            {
                if (!certificate.Equals(except))
                {
                    certificate.Dispose();
                }
            }
            certificateCollection.Clear();
        }
    }

    public static X509Certificate2 PersistKey(this X509Certificate2 fullCertificate)
    {
        // We need to force the key to be persisted.
        // See https://github.com/dotnet/runtime/issues/23749
        var certificateBytes = fullCertificate.Export(X509ContentType.Pkcs12, "");
        return new X509Certificate2(certificateBytes, "", X509KeyStorageFlags.DefaultKeySet);
    }
}
