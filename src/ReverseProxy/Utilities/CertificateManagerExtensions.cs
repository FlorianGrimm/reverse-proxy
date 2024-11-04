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
            request = that.AddRequest(request);
            certificateRequests.Add(request);
        }
        if (certificateConfigs is { })
        {
            foreach (var item in certificateConfigs)
            {
                var request = new CertificateRequest(id, item, requirement);
                request = that.AddRequest(request);
                certificateRequests.Add(request);
            }
        }
        var result = new CertificateRequestCollection(id, certificateRequests, x509Certificate2s);
        that.AddRequestCollection(result);
        return result;
    }
}
