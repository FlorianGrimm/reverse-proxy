using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public class CertificateRequestCollectionDictionary(
    ICertificateManager certificateManager,
    string prefix,
    CertificateRequirement certificateRequirement
    )
{
    private readonly ICertificateManager _certificateManager = certificateManager;
    private readonly string _prefix = prefix;
    private readonly CertificateRequirement _certificateRequirement = certificateRequirement;

    private readonly ConcurrentDictionary<string, CertificateRequestCollection> _certificateRequestCollectionById = new();

    public CertificateRequestCollection GetOrAddConfiguration(
        string id,
        CertificateConfig? clientCertificate,
        List<CertificateConfig>? clientCertificates,
        X509Certificate2Collection? clientCertificateCollection
        )
    {
        if (_certificateRequestCollectionById.TryGetValue(id, out var result))
        {
            return result;
        }

        lock (_certificateRequestCollectionById)
        {
            if (_certificateRequestCollectionById.TryGetValue(id, out result))
            {
                return result;
            }
            {
                result = Create(id, clientCertificates, clientCertificate, clientCertificateCollection);
                _certificateManager.AddRequestCollection(result);
                _ = _certificateRequestCollectionById.TryAdd(id, result);
                return result;
            }
        }
    }

    protected CertificateRequestCollection Create(
        string id,
        List<CertificateConfig>? clientCertificates,
        CertificateConfig? clientCertificate,
        X509Certificate2Collection? clientCertificateCollection)
    {
        var result = _certificateManager.AddConfiguration(
            $"{_prefix}/{id}",
            clientCertificate,
            clientCertificates,
            clientCertificateCollection,
            _certificateRequirement);
        return result;
    }
}
