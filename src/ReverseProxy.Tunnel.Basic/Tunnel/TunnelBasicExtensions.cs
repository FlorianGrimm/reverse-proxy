// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelBasicExtensions
{
    /// <summary>
    /// This adds basic tunnel authentication.
    /// </summary>
    /// <param name="builder">this</param>
    /// <param name="configuration">the configuration to bind.</param>
    /// <param name="configure">A action that is called to configure the options.</param>
    /// <returns>fluent this</returns>
    public static IReverseProxyBuilder AddTunnelServicesBasic(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = default,
        Action<TunnelAuthenticationBasicOptions>? configure = default
        )
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationBasic.WebSocket>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationBasic.Http2>());

        var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationBasicOptions>();
        if (configuration is { } || configure is { })
        {
            optionsBuilder.Configure((options) =>
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
