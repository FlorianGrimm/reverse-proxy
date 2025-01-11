// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.AspNetCore.Builder;

public static class TransportLoopbackExtensions
{
    public static IReverseProxyBuilder AddTransportLoopback(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = default,
        Action<TransportTunnelLoopbackOptions>? configure = default
    )
    {
        Microsoft.AspNetCore.Builder.TransportTunnelExtensions.TryAddTransportTunnelCore(builder);

        var services = builder.Services;
        
        services.TryAddSingleton<ILoopbackForwardHttpClientFactory, LoopbackForwardHttpClientFactory>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelLoopbackConnectionListenerFactory>());
        services.TryAddSingleton<TransportTunnelFactory>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelFactory, TransportTunnelLoopbackFactory>());

        TunnelConnectionChannelManager.RegisterTunnelConnectionChannelManagerTunnel(services);
        services.TryAddSingleton<TransportTunnelLoopbackAuthenticator, TransportTunnelLoopbackAuthenticator>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelLoopbackAuthenticator, TransportTunnelLoopbackAuthenticatorLoopback>());

        var optionsBuilder = builder.Services.AddOptions<TransportTunnelLoopbackOptions>();
        if (configuration is { } || configure is { })
        {
            _ = optionsBuilder.Configure((options) =>
            {
                if (configuration is { })
                {
                    options.Bind(configuration);
                }
                if (configure is { })
                {
                    configure(options);
                }
            });
        }

        return builder;
    }
}
