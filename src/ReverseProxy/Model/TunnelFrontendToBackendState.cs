using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace Yarp.ReverseProxy.Model;

/// <summary>
/// TODO
/// </summary>
public sealed class TunnelFrontendToBackendState
    : IEquatable<TunnelFrontendToBackendState>
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    /// <summary>
    /// The transport used for the tunnel.
    /// </summary>
    public string Transport { get; init; } = default!;

    public TunnelFrontendToBackendAuthenticationConfig Authentication { get; init; } = default!;

    private bool _forwarderHttpClientFactoryResolved;
    private IForwarderHttpClientFactory? _forwarderHttpClientFactory = default;

    public bool TryGetForwarderHttpClientFactory(
        IForwarderHttpClientFactorySelector httpClientFactorySelector,
        [MaybeNullWhen(false)] out IForwarderHttpClientFactory result)
    {
        if (_forwarderHttpClientFactoryResolved)
        {
            result = _forwarderHttpClientFactory;
            return (result is not null);
        }

        {
            var normalizeTransport = GetNormalizedTransport();
            httpClientFactorySelector.TryGetForwarderHttpClientFactory(normalizeTransport, out var found);
            _forwarderHttpClientFactory = result = found;
            _forwarderHttpClientFactoryResolved = true;
            return (result is not null);
        }
    }

    public string GetNormalizedTransport()
    {
        return !string.IsNullOrEmpty(Transport) ? Transport : "TunnelHttp2";
    }

    public override bool Equals(object? obj)
    {
        return (obj is TunnelFrontendToBackendState other) && Equals(other);
    }

    public bool Equals(TunnelFrontendToBackendState? other)
    {
        return TunnelId == other?.TunnelId
            && Transport == other.Transport
            // TODO: later && Authentication.Equals(other.Authentication)
            ;
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(
            TunnelId,
            Transport
            // TODO: later Authentication
            );
    }
}
