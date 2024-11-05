using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Utilities;
public static class CertificateManagerUtility
{
    private static readonly Oid ClientCertificateOid = new Oid("1.3.6.1.5.5.7.3.2");


    // TODO: Is it better placed i a extension?
    public static bool DoesStoreCertificateMatchesRequest(
        CertificateRequest request,
        X509Certificate2 certificate,
        Action<X509ChainPolicy>? configureChainPolicy,
        TimeProvider timeProvider)
    {
        if (request.StoreRequest is { Subject: { Length: > 0 } subject })
        {
            if (!string.Equals(certificate.Subject, subject, StringComparison.OrdinalIgnoreCase)) { return false; }
        }
        return DoesAnyCertificateMatchesRequest(request, certificate, configureChainPolicy, timeProvider);
    }

    // TODO: Is it better placed i a extension?
    public static bool DoesFileCertificateMatchesRequest(
        CertificateRequest request,
        X509Certificate2 certificate,
        Action<X509ChainPolicy>? configureChainPolicy,
        TimeProvider timeProvider)
    {
        return DoesAnyCertificateMatchesRequest(request, certificate, configureChainPolicy, timeProvider);
    }

    // TODO: Is it better placed i a extension?
    public static bool DoesAnyCertificateMatchesRequest(
        CertificateRequest request,
        X509Certificate2 certificate,
        Action<X509ChainPolicy>? configureChainPolicy,
        TimeProvider timeProvider)
    {
        // requirements that we can check without the chain
        {
            if (request.Requirement is { } certificateRequirement)
            {
                if (certificateRequirement.NeedPrivateKey)
                {
                    if (!certificate.HasPrivateKey)
                    {
                        return false;
                    }
                }
                if (certificateRequirement.ClientCertificate)
                {
                    if (!certificate.IsCertificateAllowedForClientCertificate())
                    {
                        return false;
                    }
                }
                if (certificateRequirement.SignCertificate)
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
            if (request.Requirement is { } certificateRequirement)
            {
#warning TODO
                var chainPolicy = BuildChainPolicy(certificate, certificateRequirement);
                if (configureChainPolicy is not null)
                {
                    configureChainPolicy(chainPolicy);
                }
                chain.ChainPolicy = chainPolicy;
            }
            chain.ChainPolicy.VerificationTime = timeProvider.GetUtcNow().DateTime;
#if NET7_0_OR_GREATER
            chain.ChainPolicy.VerificationTimeIgnored = false;
#endif
            if (!chain.Build(certificate))
            {
                return false;
            }
            foreach (var chainStatus in chain.ChainStatus)
            {
#warning TODO - still needed?
                if (chainStatus.Status == X509ChainStatusFlags.RevocationStatusUnknown)
                {
                    if (chain.ChainPolicy.RevocationMode == X509RevocationMode.NoCheck)
                    {
                        continue;
                    }
                }
                return false;
            }
            return true;
        }
    }


#warning TODO
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
        if (certificateRequirement.AllowCertificateSelfSigned
            && isCertificateSelfSigned)
        {
            // Turn off chain validation, because we have a self signed certificate.
            revocationFlag = X509RevocationFlag.EntireChain;
            revocationMode = X509RevocationMode.NoCheck;
            if (certificateRequirement.VerificationFlags.HasValue)
            {
                verificationFlags = certificateRequirement.VerificationFlags.Value;
            }
            else
            {
                verificationFlags = X509VerificationFlags.NoFlag;
            }
        }
        else
        {
            revocationFlag = certificateRequirement.RevocationFlag
                .GetValueOrDefault(X509RevocationFlag.EntireChain);
            revocationMode = certificateRequirement.RevocationMode
                .GetValueOrDefault(X509RevocationMode.Online);
            if (certificateRequirement.VerificationFlags.HasValue)
            {
                verificationFlags = certificateRequirement.VerificationFlags.Value;
            }
            else
            {
                verificationFlags = X509VerificationFlags.NoFlag;
            }
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

        if (isCertificateSelfSigned)
        {
            chainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;
            chainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreEndRevocationUnknown;
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
