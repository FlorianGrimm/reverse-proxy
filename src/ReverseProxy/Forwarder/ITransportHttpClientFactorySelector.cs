using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Forwarder;

public interface ITransportHttpClientFactorySelector
{
    TransportMode GetTransportMode();

    int GetOrder();

    IForwarderHttpClientFactory? GetForwarderHttpClientFactory(TransportMode transportMode, ForwarderHttpClientContext context);
}

public sealed class TransportHttpClientFactorySelector : ITransportHttpClientFactorySelector
{
    private readonly ITransportHttpClientFactorySelector[] _selectorsForwarder;
    private readonly ITransportHttpClientFactorySelector[] _selectorsTunnelHTTP2;
    private readonly ITransportHttpClientFactorySelector[] _selectorsTunnelWebSocket;

    public TransportHttpClientFactorySelector(
        IEnumerable<ITransportHttpClientFactorySelector> forwarderHttpClientFactorySelectors
        )
    {
        var selectors = forwarderHttpClientFactorySelectors.ToArray();

        _selectorsForwarder = selectors
            .Where(s => s.GetTransportMode() switch {
                TransportMode.Invalid => true,
                TransportMode.Forwarder => true,
                _ => false
            })
            .OrderByDescending(s => s.GetOrder())
            .ToArray();

        _selectorsTunnelHTTP2 = selectors
            .Where(s => s.GetTransportMode() switch {
                TransportMode.Invalid => true,
                TransportMode.TunnelHTTP2 => true,
                _ => false
            })
            .OrderByDescending(s => s.GetOrder())
            .ToArray();

        _selectorsTunnelWebSocket = selectors
            .Where(s => s.GetTransportMode() switch {
                TransportMode.Invalid => true,
                TransportMode.TunnelWebSocket => true,
                _ => false
            })
            .OrderByDescending(s => s.GetOrder())
            .ToArray();
    }

    public TransportMode GetTransportMode() => TransportMode.Invalid;

    public int GetOrder() => 0;

    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(TransportMode transportMode, ForwarderHttpClientContext context)
    {
        var selectors = transportMode switch
        {
            TransportMode.Forwarder => _selectorsForwarder,
            TransportMode.TunnelHTTP2 => _selectorsTunnelHTTP2,
            TransportMode.TunnelWebSocket => _selectorsTunnelWebSocket,
            _ => null
        };
        if (selectors is null) { return default; }

        foreach (var selector in selectors)
        {
            var factory = selector.GetForwarderHttpClientFactory(transportMode, context);
            if (factory is not null)
            {
                return factory;
            }
        }
        return default;
    }

}
