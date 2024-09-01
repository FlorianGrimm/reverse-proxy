// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationConfigService
    : ITunnelAuthenticationConfigService
{
    private readonly List<ITunnelAuthenticationService> _services;
    private ImmutableDictionary<string, ImmutableDictionary<string, ITunnelAuthenticationService>> _servicesByTransportAuthenticationMode;

    public TunnelAuthenticationConfigService(
        IEnumerable<ITunnelAuthenticationService> tunnelAuthenticationConfigServices)
    {
        _services = tunnelAuthenticationConfigServices.ToList();
        _servicesByTransportAuthenticationMode = ImmutableDictionary<string, ImmutableDictionary<string, ITunnelAuthenticationService>>.Empty.WithComparers(StringComparer.OrdinalIgnoreCase);
    }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        foreach (var service in _services)
        {
            service.ConfigureKestrelServer(kestrelServerOptions);
        }
    }

    public IReadOnlyCollection<ITunnelAuthenticationService> GetTunnelAuthenticationServices(string transport)
    {
        return GetTunnelAuthenticationServicesByTransport(transport).Values.ToImmutableArray();
    }

    public bool TryGetTunnelAuthenticationServices(string transport, string authenticationMode, [MaybeNullWhen(false)] out ITunnelAuthenticationService result)
    {
        if (!_servicesByTransportAuthenticationMode.TryGetValue(transport, out var servicesByTransport))
        {
            servicesByTransport = GetTunnelAuthenticationServicesByTransport(transport);
        }
        return servicesByTransport.TryGetValue(authenticationMode, out result);
    }

    private ImmutableDictionary<string, ITunnelAuthenticationService> GetTunnelAuthenticationServicesByTransport(string transport)
    {
        ImmutableDictionary<string, ITunnelAuthenticationService>? result = default;
        while (true)
        {
            var servicesByTransportAuthenticationMode = _servicesByTransportAuthenticationMode;
            if (servicesByTransportAuthenticationMode.TryGetValue(transport, out var found))
            {
                return found;
            }

            if (result is null)
            {
                var dict = new Dictionary<string, ITunnelAuthenticationService>();
                foreach (var service in _services)
                {
                    var serviceTransport = service.GetTransport();
                    if (string.Equals(serviceTransport, transport, StringComparison.OrdinalIgnoreCase))
                    {
                        dict.Add(service.GetAuthenticationMode(), service);
                    }
                }
                result = dict.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
            }
            var servicesByTransportAuthenticationModeNext = servicesByTransportAuthenticationMode.Add(transport, result);
            if (ReferenceEquals(
                servicesByTransportAuthenticationMode,
                System.Threading.Interlocked.CompareExchange(ref _servicesByTransportAuthenticationMode, servicesByTransportAuthenticationModeNext, servicesByTransportAuthenticationMode)
                ))
            {
                return result;
            }

            // the _servicesByTransportAuthenticationMode was modified so retry
            continue;
        }
    }
}
