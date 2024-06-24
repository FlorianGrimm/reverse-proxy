using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Configuration.ClusterValidators;

internal class TransportValidator : IClusterValidator
{
    public ValueTask ValidateAsync(ClusterConfig cluster, IList<Exception> errors)
    {
        if (!cluster.IsTunnelTransport) { return ValueTask.CompletedTask; }

        var clusterId = cluster.ClusterId;
        if (string.IsNullOrEmpty(clusterId))
        {
            errors.Add(new ArgumentException("Cluster ClusterId is not set."));
        }
        {
            var containsInvalidChars = false;
            foreach (var c in clusterId)
            {
                if (!char.IsLetterOrDigit(c))
                {
                    containsInvalidChars = true;
                    break;
                }
            }
            if (containsInvalidChars)
            {
                errors.Add(new ArgumentException("Cluster ClusterId contains invalid characters."));
            }
        }
        if (clusterId.Length > 100)
        {
            errors.Add(new ArgumentException("Cluster ClusterId is too long."));
        }
        return ValueTask.CompletedTask;
    }
}
