using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Yarp.ReverseProxy.Forwarder;

public sealed class TransportForwarderHttpClientFactorySelector
{
    private readonly ImmutableDictionary<string, ITransportForwarderHttpClientFactorySelector> _selectorByName;

    public TransportForwarderHttpClientFactorySelector(
        IEnumerable<ITransportForwarderHttpClientFactorySelector> forwarderHttpClientFactorySelectors
        )
    {
        var dict = new Dictionary<string, ITransportForwarderHttpClientFactorySelector>(StringComparer.OrdinalIgnoreCase);
        foreach (var selector in forwarderHttpClientFactorySelectors)
        {
            dict.Add(selector.GetTransportMode(), selector);
        }
        _selectorByName = dict.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    public IEnumerable<string> GetTransportModes() => _selectorByName.Keys;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(string transportMode, ForwarderHttpClientContext context)
    {
        if (string.IsNullOrEmpty(transportMode))
        {
            transportMode = TransportForwarderHttpClientFactory.TransportMode;
        }
        if (_selectorByName.TryGetValue(transportMode, out var selector))
        {
            return selector.GetForwarderHttpClientFactory(context);
        }
        else
        {
            return null;
        }
    }

}
