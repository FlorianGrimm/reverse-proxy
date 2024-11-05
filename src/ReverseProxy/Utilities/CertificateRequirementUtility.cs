using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public static class CertificateRequirementUtility
{
    public static CertificateRequirement CombineQ(
        CertificateRequirement? certificateRequirement,
        CertificateRequirement? additionalRequirement)
    {
        return certificateRequirement.HasValue && additionalRequirement.HasValue
            ? Combine(certificateRequirement.Value, additionalRequirement.Value)
            : (certificateRequirement ?? additionalRequirement ?? new())
            ;
    }

    public static CertificateRequirement Combine(
        CertificateRequirement certificateRequirement,
        CertificateRequirement additionalRequirement)
    {
        var clientCertificate = certificateRequirement.ClientCertificate || additionalRequirement.ClientCertificate;
        var signCertificate = certificateRequirement.SignCertificate || additionalRequirement.SignCertificate;
        var needPrivateKey = clientCertificate || certificateRequirement.NeedPrivateKey || additionalRequirement.NeedPrivateKey;

        var allowCertificateSelfSigned = certificateRequirement.AllowCertificateSelfSigned || certificateRequirement.AllowCertificateSelfSigned;

        X509RevocationFlag? revocationFlag = (certificateRequirement.RevocationFlag, additionalRequirement.RevocationFlag) switch
        {
            (_, X509RevocationFlag.EntireChain) => X509RevocationFlag.EntireChain,
            (X509RevocationFlag.EntireChain, _) => X509RevocationFlag.EntireChain,
            (X509RevocationFlag.ExcludeRoot, _) => X509RevocationFlag.ExcludeRoot,
            (_, X509RevocationFlag.ExcludeRoot) => X509RevocationFlag.ExcludeRoot,
            (X509RevocationFlag.EndCertificateOnly, _) => X509RevocationFlag.EndCertificateOnly,
            (_, X509RevocationFlag.EndCertificateOnly) => X509RevocationFlag.EndCertificateOnly,
            _ => default
        };

        X509RevocationMode? revocationMode = (certificateRequirement.RevocationMode, additionalRequirement.RevocationMode) switch
        {
            (_, X509RevocationMode.Online) => X509RevocationMode.Online,
            (X509RevocationMode.Online, _) => X509RevocationMode.Online,
            (_, X509RevocationMode.Offline) => X509RevocationMode.Offline,
            (X509RevocationMode.Offline, _) => X509RevocationMode.Offline,
            (_, X509RevocationMode.NoCheck) => X509RevocationMode.NoCheck,
            (X509RevocationMode.NoCheck, _) => X509RevocationMode.NoCheck,
            _ => default
        };

        var verificationFlags = certificateRequirement.VerificationFlags.HasValue || additionalRequirement.VerificationFlags.HasValue
            ? (certificateRequirement.VerificationFlags ?? default) | (additionalRequirement.VerificationFlags ?? default)
            : (X509VerificationFlags?)default;

        var validateValidityPeriod = (certificateRequirement.ValidateValidityPeriod, additionalRequirement.ValidateValidityPeriod) switch
        {
            (true, _) => true,
            (_, true) => true,
            (false, _) => false,
            (_, false) => false,
            _ => (bool?)null
        };
        var trustMode = (certificateRequirement.TrustMode, additionalRequirement.TrustMode) switch
        {
            (X509ChainTrustMode.CustomRootTrust, _) => X509ChainTrustMode.CustomRootTrust,
            (_, X509ChainTrustMode.CustomRootTrust) => X509ChainTrustMode.CustomRootTrust,
            (X509ChainTrustMode.System, _) => X509ChainTrustMode.System,
            (_, X509ChainTrustMode.System) => X509ChainTrustMode.System,
            _ => (X509ChainTrustMode?)null
        };
        var customTrustStore = X509Certificate2Extensions.Concat(certificateRequirement.CustomTrustStore, additionalRequirement.CustomTrustStore);
        var additionalChainCertificates = X509Certificate2Extensions.Concat(certificateRequirement.AdditionalChainCertificates, additionalRequirement.AdditionalChainCertificates);

        return new CertificateRequirement(
            ClientCertificate: clientCertificate,
            SignCertificate: signCertificate,
            NeedPrivateKey: needPrivateKey,
            AllowCertificateSelfSigned: allowCertificateSelfSigned,

            RevocationFlag: revocationFlag,
            RevocationMode: revocationMode,
            VerificationFlags: verificationFlags,

            ValidateValidityPeriod: validateValidityPeriod,
            TrustMode: trustMode,
            CustomTrustStore: customTrustStore,
            AdditionalChainCertificates: additionalChainCertificates);
    }

    public static (
      CertificateFileRequest fileRequest,
      CertificateRequirement requirement
      ) CombineFileCertificateRequest(
      CertificateRequirement requirement,
      List<CertificateRequest> requests)
    {
        string? path = null;
        string? keyPath = null;
        string? password = null;
        foreach (var request in requests)
        {
            if (request.FileRequest is { } requestFileRequest)
            {
                if (requestFileRequest.Path is { Length: > 0 } requestPath)
                {
                    path = requestPath;
                }
                if (requestFileRequest.KeyPath is { Length: > 0 } requestKeyPath)
                {
                    keyPath = requestKeyPath;
                }
                if (requestFileRequest.Password is { Length: > 0 } requestPassword)
                {
                    password = requestPassword;
                }
            }
            requirement = CertificateRequirementUtility.CombineQ(requirement, request.Requirement);
        }

        return (new CertificateFileRequest(path, keyPath, password), requirement);
    }

}
