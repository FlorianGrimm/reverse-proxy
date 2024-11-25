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
    /// <summary>
    /// Concatenates two <see cref="X509Certificate2Collection"/> objects.
    /// </summary>
    /// <param name="a">The first <see cref="X509Certificate2Collection"/>.</param>
    /// <param name="b">The second <see cref="X509Certificate2Collection"/>.</param>
    /// <returns>
    /// A new <see cref="X509Certificate2Collection"/> containing the certificates from both input collections,
    /// or one of the input collections if the other is null, or null if both input collections are null.
    /// </returns>
    public static X509Certificate2Collection? Concat(X509Certificate2Collection? a, X509Certificate2Collection? b)
    {
        if (a is not null && b is not null)
        {
            var result = new X509Certificate2Collection();
            result.AddRange(a);
            result.AddRange(b);
            return result;
        }
        if (a is not null && b is null) { return a; }
        if (a is null && b is not null) { return b; }
        return null;
    }

    public const string ClientCertificateOid = "1.3.6.1.5.5.7.3.2";

    /// <summary>
    /// Determines if the certificate is allowed for client authentication based on the Extended Key Usage extension./// ///
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to check.</param>
    /// <returns>
    /// True if the certificate is allowed for client authentication, otherwise false.
    /// </returns>
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

    /// <summary>
    /// Determines if the certificate is allowed for a specific key usage based on the X509 Key Usage extension.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to check.</param>
    /// <param name="keyUsage">The <see cref="X509KeyUsageFlags"/> to check for.</param>
    /// <returns>
    /// True if the certificate is allowed for the specified key usage, otherwise false.
    /// </returns>
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


    /// <summary>
    /// Determines if the certificate is allowed for a specific key usage based on the X509 Enhanced Key Usage extension.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to check.</param>
    /// <param name="keyUsageOid">The OID of the key usage to check for.</param>
    /// <returns>
    /// True if the certificate is allowed for the specified key usage, otherwise false.
    /// </returns>
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
    public static bool IsSelfSignedCertificate(this X509Certificate2 certificate)
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

    /// <summary>
    /// Disposes all certificates in the collection except the specified certificate.
    /// </summary>
    /// <param name="certificateCollection">The <see cref="X509Certificate2Collection"/> to dispose certificates from.</param>
    /// <param name="except">The <see cref="X509Certificate"/> to exclude from disposal.</param>
    public static void DisposeCertificatesExcept(
            this X509Certificate2Collection? certificateCollection,
            X509Certificate? except = default
            )
    {
        if (certificateCollection is null) { return; }

        foreach (var certificate in certificateCollection)
        {
            if ((except is null) || (!certificate.Equals(except)))
            {
                certificate.Dispose();
            }
        }
        certificateCollection.Clear();
    }

    /// <summary>
    /// Disposes all certificates in the collection except the specified certificates.
    /// </summary>
    /// <param name="certificateCollection">The <see cref="X509Certificate2Collection"/> to dispose certificates from.</param>
    /// <param name="exceptCollection">The certificates to exclude from disposal.</param>
    public static void DisposeCertificatesExceptCollection(
            this X509Certificate2Collection? certificateCollection,
            X509Certificate2Collection exceptCollection
            )
    {
        if (certificateCollection is null) { return; }

        foreach (var certificate in certificateCollection)
        {
            var found = false;
            foreach (var exceptCertificate in exceptCollection) {
                if (exceptCertificate.Equals(certificate)) {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                certificate.Dispose();
            }
        }
        certificateCollection.Clear();
    }


    /// <summary>
    /// Forces the key of the certificate to be persisted.
    /// </summary>
    /// <param name="fullCertificate">The <see cref="X509Certificate2"/> to persist the key for.</param>
    /// <returns>A new <see cref="X509Certificate2"/> with the key persisted.</returns>
    public static X509Certificate2 PersistKey(this X509Certificate2 fullCertificate)
    {
        // We need to force the key to be persisted.
        // See https://github.com/dotnet/runtime/issues/23749
        var certificateBytes = fullCertificate.Export(X509ContentType.Pkcs12, "");
        return new X509Certificate2(certificateBytes, "", X509KeyStorageFlags.DefaultKeySet);
    }

    public static void ValidateCertificate(
        this X509Certificate2Collection? that,
        ICertificateVerifier certificateVerifier,
        System.DateTime localNow
        )
    {
        if (that is null) { return; }

        var index = 0;
        while (index < that.Count)
        {
            var certificate = that[index];
            if (certificateVerifier.ValidateCertificate(certificate, localNow))
            {
                //OK
                index++;
            }
            else
            {
                that.RemoveAt(index);
            }
        }
    }

    /// <summary>
    /// Gets the NotBefore date of the certificate, or a default value if an exception occurs.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to get the NotBefore date from.</param>
    /// <param name="defaultValue">The default value to return if an exception occurs.</param>
    /// <returns>The NotBefore date of the certificate, or the default value if an exception occurs.</returns>
    public static DateTime GetNotBeforeOrDefault(this X509Certificate2 certificate, DateTime? defaultValue)
    {
        try
        {
            return certificate.NotBefore;
        }
        catch
        {
            if (defaultValue.HasValue)
            {
                return defaultValue.Value;
            }
            else
            {
                return DateTime.MinValue;
            }
        }
    }

    /// <summary>
    /// Gets the NotAfter date of the certificate, or a default value if an exception occurs.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/> to get the NotAfter date from.</param>
    /// <param name="defaultValue">The default value to return if an exception occurs.</param>
    /// <returns>The NotAfter date of the certificate, or the default value if an exception occurs.</returns>
    public static DateTime GetNotAfterOrDefault(this X509Certificate2 certificate, DateTime? defaultValue)
    {
        try
        {
            return certificate.NotAfter;
        }
        catch
        {
            if (defaultValue.HasValue)
            {
                return defaultValue.Value;
            }
            else
            {
                return DateTime.MinValue;
            }
        }
    }
}
