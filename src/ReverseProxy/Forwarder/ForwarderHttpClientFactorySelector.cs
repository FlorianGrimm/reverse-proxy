// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Forwarder;

public class ForwarderTransportClientFactorySelector : ForwarderHttpClientFactory, IForwarderTransportClientFactorySelector
{
    private readonly Dictionary<string, IForwarderTransportClientFactory> _forwarderTransportClientFactories;

    public ForwarderTransportClientFactorySelector(
        IEnumerable<IForwarderTransportClientFactory> forwarderTransportHttpClientFactories
        )
    {
        var buildForwarderTransportHttpClientFactories = new Dictionary<string, IForwarderTransportClientFactory>(StringComparer.OrdinalIgnoreCase);
        foreach (var factory in forwarderTransportHttpClientFactories)
        {
            var transport = factory.GetTransport();
            var normalizedTransport = string.IsNullOrEmpty(transport) ? "HTTP" : transport;
            buildForwarderTransportHttpClientFactories.Add(normalizedTransport, factory);
        }
        _forwarderTransportClientFactories = buildForwarderTransportHttpClientFactories;

    }
    public IForwarderHttpClientFactory GetForwarderHttpClientFactory(ClusterConfig incomingCluster)
    {
        var transport = incomingCluster.Transport;
        var normalizedTransport = string.IsNullOrEmpty(transport) ? "HTTP" : transport;
        if (!_forwarderTransportClientFactories.TryGetValue(normalizedTransport, out var factory))
        {
            // TODO: HERE
            throw new System.NotImplementedException();
        }
        return factory;

    }
}
