// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Yarp.ReverseProxy.Forwarder;

public interface IForwarderHttpClientFactorySelector
{
    bool TryGetForwarderHttpClientFactory(string transport, [MaybeNullWhen(false)] out IForwarderHttpClientFactory factory);
}

public class ForwarderHttpClientFactorySelector : IForwarderHttpClientFactorySelector
{
    private readonly Dictionary<string, IForwarderHttpClientFactorySelectiv> _forwarderHttpClientFactoryByTransport;

    public ForwarderHttpClientFactorySelector(
        IEnumerable<IForwarderHttpClientFactorySelectiv> forwarderHttpClientFactories
        )
    {
        Dictionary<string, IForwarderHttpClientFactorySelectiv> forwarderHttpClientFactoryByTransport = new(StringComparer.OrdinalIgnoreCase);
        foreach (var forwarderHttpClientFactory in forwarderHttpClientFactories)
        {
            var transport = forwarderHttpClientFactory.GetTransport();
            forwarderHttpClientFactoryByTransport.Add(transport, forwarderHttpClientFactory);
        }
        _forwarderHttpClientFactoryByTransport = forwarderHttpClientFactoryByTransport;
    }

    public bool TryGetForwarderHttpClientFactory(string transport, [MaybeNullWhen(false)] out IForwarderHttpClientFactory factory)
    {
        if (_forwarderHttpClientFactoryByTransport.TryGetValue(transport, out var value))
        {
            factory = value;
            return true;
        }
        else
        {
            factory = default;
            return false;
        }
    }
}
