// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Tunnel;
using Yarp.ReverseProxy.Utilities;

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
