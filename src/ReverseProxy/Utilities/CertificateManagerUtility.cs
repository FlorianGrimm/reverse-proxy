using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy.Utilities;
public static class CertificateManagerUtility
{
    public static readonly Oid ClientCertificateOid = new Oid("1.3.6.1.5.5.7.3.2");


    /// <summary>
    /// Validates the <paramref name="certificate"/> against the <paramref name="request"/>,
    /// respecting that this certificate is loaded from a store.
    /// </summary>
    /// <param name="request">the request that was used to load the <paramref name="certificate"/>.</param>
    /// <param name="requirement">the requirement from options + request</param>
    /// <param name="certificate">the loaded certificate.</param>
    /// <param name="configureChainPolicy">configure the <see cref="X509ChainPolicy"/>.</param>
    /// <param name="timeProvider">optional (default TimeProvider.System)</param>
    /// <param name="logger">logger for errors</param>
    /// <returns>true if valid</returns>
    public static bool DoesStoreCertificateMatchesRequest(
        CertificateRequest request,
        CertificateRequirement requirement,
        X509Certificate2 certificate,
        Action<X509ChainPolicy>? configureChainPolicy,
        TimeProvider? timeProvider,
        ILogger logger)
    {
        if (request.StoreRequest is { Subject: { Length: > 0 } subject })
        {
            if (!string.Equals(certificate.Subject, subject, StringComparison.OrdinalIgnoreCase)) { return false; }
        }
        return DoesAnyCertificateMatchesRequest(
            request,
            requirement,
            certificate,
            configureChainPolicy,
            timeProvider,
            logger);
    }

    /// <summary>
    /// Validates the <paramref name="certificate"/> against the <paramref name="request"/>,
    /// respecting that this certificate is loaded from a file.
    /// </summary>
    /// <param name="request">the request that was used to load the <paramref name="certificate"/>.</param>
    /// <param name="requirement">the requirement from options + request</param>
    /// <param name="certificate">the loaded certificate.</param>
    /// <param name="configureChainPolicy">configure the <see cref="X509ChainPolicy"/>.</param>
    /// <param name="timeProvider">optional (default TimeProvider.System)</param>
    /// <param name="logger">logger for errors</param>
    /// <returns>true if valid</returns>
    public static bool DoesFileCertificateMatchesRequest(
        CertificateRequest request,
        CertificateRequirement requirement,
        X509Certificate2 certificate,
        Action<X509ChainPolicy>? configureChainPolicy,
        TimeProvider? timeProvider,
        ILogger logger)
    {
        return DoesAnyCertificateMatchesRequest(
            request,
            requirement,
            certificate,
            configureChainPolicy,
            timeProvider,
            logger);
    }

    /// <summary>
    /// Validates the <paramref name="certificate"/> against the <paramref name="request"/>.
    /// </summary>
    /// <param name="request">the request that was used to load the <paramref name="certificate"/>.</param>
    /// <param name="requirement">the requirement from options + request</param>
    /// <param name="certificate">the loaded certificate.</param>
    /// <param name="configureChainPolicy">configure the <see cref="X509ChainPolicy"/>.</param>
    /// <param name="timeProvider">optional (default TimeProvider.System)</param>
    /// <param name="logger">logger for errors</param>
    /// <returns>true if valid</returns>
    public static bool DoesAnyCertificateMatchesRequest(
        CertificateRequest request,
        CertificateRequirement requirement,
        X509Certificate2 certificate,
        Action<X509ChainPolicy>? configureChainPolicy,
        TimeProvider? timeProvider,
        ILogger logger)
    {
        // requirements that we can check without the chain
        {
            //if (request.Requirement is { } requirement)
            {
                if (requirement.NeedPrivateKey)
                {
                    if (!certificate.HasPrivateKey)
                    {
                        return false;
                    }
                }
                if (requirement.ClientCertificate)
                {
                    if (!certificate.IsCertificateAllowedForClientCertificate())
                    {
                        return false;
                    }
                }
                if (requirement.SignCertificate)
                {
                    if (!certificate.IsCertificateAllowedForX509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature))
                    {
                        return false;
                    }
                }
            }
        }

        using (X509Chain chain = new())
        {
            // convert the requirement to the chain policy
            //if (request.Requirement is { } certificateRequirement)
            {
                var chainPolicy = BuildChainPolicy(certificate, requirement);
                if (configureChainPolicy is not null)
                {
                    configureChainPolicy(chainPolicy);
                }
                chain.ChainPolicy = chainPolicy;
            }
            chain.ChainPolicy.VerificationTime = (timeProvider ?? TimeProvider.System).GetUtcNow().DateTime;
#if NET7_0_OR_GREATER
            chain.ChainPolicy.VerificationTimeIgnored = false;
#endif
            if (!chain.Build(certificate))
            {
                logger.LogWarning("Certificate Subject: {Subject}", certificate.Subject);
                foreach (var chainStatus in chain.ChainStatus)
                {
                    logger.LogWarning("Chain status: {Status} {StatusInformation}", chainStatus.Status, chainStatus.StatusInformation);
                }
                return false;
            }
            return true;
        }
    }


    public static X509ChainPolicy BuildChainPolicy(
        X509Certificate2 certificate,
        CertificateRequirement certificateRequirement
        )
    {
        // Now build the chain validation options.
        X509RevocationFlag revocationFlag;
        X509RevocationMode revocationMode;
        X509VerificationFlags verificationFlags;

        var isCertificateSelfSigned = certificate.IsSelfSignedCertificate();
        if (certificateRequirement.AllowCertificateSelfSigned && isCertificateSelfSigned)
        {
            // Turn off chain validation, because we have a self signed certificate.
            revocationFlag = X509RevocationFlag.EndCertificateOnly;
            revocationMode = X509RevocationMode.NoCheck;

            verificationFlags = certificateRequirement.VerificationFlags.GetValueOrDefault(X509VerificationFlags.NoFlag)
                    | X509VerificationFlags.IgnoreNotTimeValid
                    | X509VerificationFlags.AllowUnknownCertificateAuthority
                    | X509VerificationFlags.IgnoreRootRevocationUnknown
                    ;
        }
        else
        {
            revocationFlag = certificateRequirement.RevocationFlag
                .GetValueOrDefault(X509RevocationFlag.EntireChain);
            revocationMode = certificateRequirement.RevocationMode
                .GetValueOrDefault(X509RevocationMode.Online);
            verificationFlags = certificateRequirement.VerificationFlags.GetValueOrDefault(X509VerificationFlags.NoFlag);
        }

        var chainPolicy = new X509ChainPolicy
        {
            RevocationFlag = revocationFlag,
            RevocationMode = revocationMode,
        };


        if (certificateRequirement.ClientCertificate)
        {
            chainPolicy.ApplicationPolicy.Add(ClientCertificateOid);
        }

        if (certificateRequirement.AllowCertificateSelfSigned && isCertificateSelfSigned)
        {
            chainPolicy.VerificationFlags |=
                  X509VerificationFlags.AllowUnknownCertificateAuthority
                | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreRootRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown;
            chainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chainPolicy.CustomTrustStore.Add(certificate);
            chainPolicy.ExtraStore.Add(certificate);
        }
        else
        {
            if (certificateRequirement.CustomTrustStore is { } customTrustStore)
            {
                chainPolicy.CustomTrustStore.AddRange(customTrustStore);
                chainPolicy.TrustMode = certificateRequirement.TrustMode
                    .GetValueOrDefault(X509ChainTrustMode.CustomRootTrust);
            }
            else
            {
                chainPolicy.TrustMode = certificateRequirement.TrustMode
                    .GetValueOrDefault(X509ChainTrustMode.System);
            }
        }

        if (certificateRequirement.AdditionalChainCertificates is { Count: > 0 } additionalChainCertificates)
        {
            chainPolicy.ExtraStore.AddRange(additionalChainCertificates);
        }

        if (certificateRequirement.ValidateValidityPeriod.GetValueOrDefault(true))
        {
            // Validate
        }
        else
        {
            chainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;
        }

        return chainPolicy;
    }

}
