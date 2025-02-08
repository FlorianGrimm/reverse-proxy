// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Transport;

namespace Microsoft.AspNetCore.Builder;

public static class WebHostBuilderExtensions
{
    /// <summary>
    /// This adds basic tunnel authentication.
    /// </summary>
    /// <param name="builder">this builder</param>
    /// <param name="configuration">Configuration </param>
    /// <param name="configure">Action to configure the <see cref="TransportTunnelAuthenticationBasicOptions"/></param>
    /// <returns>fluent htis</returns>
    public static IReverseProxyBuilder AddTransportTunnelBasic(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = default,
        Action<TransportTunnelAuthenticationBasicOptions>? configure = default
        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authenticator, TransportTunnelHttp2AuthenticatorBasic>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthenticator, TransportTunnelWebSocketAuthenticatorBasic>());

        var optionsBuilder = builder.Services.AddOptions<TransportTunnelAuthenticationBasicOptions>();
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
