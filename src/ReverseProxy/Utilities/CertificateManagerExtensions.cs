using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public static class CertificateManagerExtensions
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

        return new CertificateRequirement(
            ClientCertificate: clientCertificate,
            SignCertificate: signCertificate,
            NeedPrivateKey: needPrivateKey,
            RevocationFlag: revocationFlag,
            RevocationMode: revocationMode,
            VerificationFlags: verificationFlags);
    }

    public static CertificateRequestCollection TryAddConfiguration(
        this ICertificateManager that,
        ConcurrentDictionary<string, CertificateRequestCollection> dict,
        string id,
        Func<CertificateRequestCollection> factory
        )
    {
        lock (dict)
        {
            if (dict.TryGetValue(id, out var certificateRequestCollection))
            {
                //OK
                return certificateRequestCollection;
            }
            else
            {
                certificateRequestCollection = factory();
                that.AddRequestCollection(certificateRequestCollection);
                dict.TryAdd(id, certificateRequestCollection);
                return certificateRequestCollection;
            }
        }
    }



    public static CertificateRequestCollection AddConfiguration(
        this ICertificateManager that,
        string id,
        CertificateConfig? certificateConfig,
        List<CertificateConfig>? certificateConfigs,
        X509Certificate2Collection? x509Certificate2s,
        CertificateRequirement requirement)
    {
        var certificateRequests = new List<CertificateRequest>();
        if (certificateConfig is { })
        {
            var request = new CertificateRequest(id, certificateConfig, requirement);
            certificateRequests.Add(request);
            that.AddRequest(request);
        }
        if (certificateConfigs is { })
        {
            foreach (var item in certificateConfigs)
            {
                var request = new CertificateRequest(id, item, requirement);
                certificateRequests.Add(request);
                that.AddRequest(request);
            }
        }
        var result = new CertificateRequestCollection(id, certificateRequests, x509Certificate2s);
        that.AddRequestCollection(result);
        return result;
    }
}
