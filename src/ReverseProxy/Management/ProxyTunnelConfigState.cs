// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Management;

internal class ProxyTunnelConfigState : IProxyTunnelStateLookup
{
    public readonly ImmutableDictionary<string, TunnelFrontendToBackendState> TunnelFrontendToBackendByTunnelId;
    public readonly ImmutableDictionary<string, TunnelBackendToFrontendState> TunnelBackendToFrontendByTunnelId;

    public ProxyTunnelConfigState(
        List<TunnelFrontendToBackendState> tunnelFrontendToBackends,
        List<TunnelBackendToFrontendState> tunnelBackendToFrontends)
    {
        var dictTunnelFrontendToBackend = ImmutableDictionary<string, TunnelFrontendToBackendState>.Empty.WithComparers(StringComparer.OrdinalIgnoreCase);
        foreach (var tunnelFrontendToBackend in tunnelFrontendToBackends)
        {
            dictTunnelFrontendToBackend = dictTunnelFrontendToBackend.Add(tunnelFrontendToBackend.TunnelId, tunnelFrontendToBackend);
        }

        var dictTunnelBackendToFrontend = ImmutableDictionary<string, TunnelBackendToFrontendState>.Empty.WithComparers(StringComparer.OrdinalIgnoreCase);
        foreach (var tunnelBackendToFrontend in tunnelBackendToFrontends)
        {
            dictTunnelBackendToFrontend = dictTunnelBackendToFrontend.Add(tunnelBackendToFrontend.TunnelId, tunnelBackendToFrontend);
        }

        TunnelFrontendToBackendByTunnelId = dictTunnelFrontendToBackend;
        TunnelBackendToFrontendByTunnelId = dictTunnelBackendToFrontend;
    }

    public IEnumerable<TunnelFrontendToBackendState> GetTunnelFrontendToBackends()
    {
        return TunnelFrontendToBackendByTunnelId.Values;
    }

    public bool TryGetTunnelFrontendToBackend(string tunnelId, [MaybeNullWhen(false)] out TunnelFrontendToBackendState state)
    {
        return TunnelFrontendToBackendByTunnelId.TryGetValue(tunnelId, out state);
    }


    public IEnumerable<TunnelBackendToFrontendState> GetTunnelBackendToFrontends()
    {
        return TunnelBackendToFrontendByTunnelId.Values;
    }

    public bool TryGetTunnelBackendToFrontend(string tunnelId, [MaybeNullWhen(false)] out TunnelBackendToFrontendState state)
    {
        return TunnelBackendToFrontendByTunnelId.TryGetValue(tunnelId, out state);
    }
}
