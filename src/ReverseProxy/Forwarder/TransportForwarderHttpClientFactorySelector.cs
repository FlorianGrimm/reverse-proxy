using System;
using System.Collections.Generic;
using System.Collections.Immutable;

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy.Forwarder;

/// <summary>
/// The <see cref="TransportForwarderHttpClientFactorySelector"/> class is responsible for selecting the appropriate
/// <see cref="ITransportForwarderHttpClientFactorySelector"/> based on the transport mode.
/// </summary>
public sealed partial class TransportForwarderHttpClientFactorySelector
{
    private readonly ImmutableDictionary<string, ITransportForwarderHttpClientFactorySelector> _selectorByName;
    private readonly ILogger<TransportForwarderHttpClientFactorySelector> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TransportForwarderHttpClientFactorySelector"/> class.
    /// </summary>
    /// <param name="forwarderHttpClientFactorySelectors">A collection of <see cref="ITransportForwarderHttpClientFactorySelector"/> implementations.</param>
    /// <param name="logger">The logger instance used for logging.</param>
    public TransportForwarderHttpClientFactorySelector(
        IEnumerable<ITransportForwarderHttpClientFactorySelector> forwarderHttpClientFactorySelectors,
        ILogger<TransportForwarderHttpClientFactorySelector> logger
        )
    {
        _logger = logger;
        var dictFactoryByTransport = new Dictionary<string, ITransportForwarderHttpClientFactorySelector>(StringComparer.OrdinalIgnoreCase);
        foreach (var selector in forwarderHttpClientFactorySelectors)
        {
            var transport = selector.GetTransport();
            if (dictFactoryByTransport.ContainsKey(transport))
            {
                Log.TransportIsNotUnique(logger, transport);
            }
            dictFactoryByTransport.Add(transport, selector);
        }
        _selectorByName = dictFactoryByTransport.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Gets the available transport modes.
    /// </summary>
    /// <returns>An enumerable of transport mode names.</returns>
    public IEnumerable<string> GetTransportModes() => _selectorByName.Keys;

    /// <summary>
    /// Gets the <see cref="IForwarderHttpClientFactory"/> for the specified transport mode.
    /// </summary>
    /// <param name="transportMode">The transport mode name.</param>
    /// <param name="context">The context for the forwarder HTTP client.</param>
    /// <returns>The <see cref="IForwarderHttpClientFactory"/> if found; otherwise, null.</returns>
    public IForwarderHttpClientFactory? GetForwarderHttpClientFactory(string transportMode, ForwarderHttpClientContext context)
    {
        if (string.IsNullOrEmpty(transportMode))
        {
            transportMode = Yarp.ReverseProxy.Tunnel.TunnelConstants.TransportNameForwarder;
        }
        if (_selectorByName.TryGetValue(transportMode, out var selector))
        {
            return selector.GetForwarderHttpClientFactory(context);
        }
        else
        {
            Log.TransportIsUnknown(_logger, transportMode);
            return null;
        }
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, Exception?> _transportIsNotUnique = LoggerMessage.Define<string>(
            LogLevel.Error,
            EventIds.TransportIsNotUnique,
            "Transport '{transport}' must be unique.");

        public static void TransportIsNotUnique(ILogger logger, string transport)
        {
            _transportIsNotUnique(logger, transport, null);
        }

        private static readonly Action<ILogger, string, Exception?> _transportIsUnknown = LoggerMessage.Define<string>(
            LogLevel.Warning,
            EventIds.TransportIsUnknown,
            "Transport '{transport}' is unknown.");

        public static void TransportIsUnknown(ILogger logger, string transport)
        {
            _transportIsUnknown(logger, transport, null);
        }
    }
}
