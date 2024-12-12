// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelAuthenticationExtensions
{
    public static AuthenticationBuilder AddTunnelAuthentication(
         this AuthenticationBuilder builder,
         string? authenticationScheme = default,
         IConfiguration? configuration = default,
         Action<Yarp.ReverseProxy.Tunnel.TunnelAuthenticationOptions>? configure = default
         )
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }

        if (string.IsNullOrEmpty(authenticationScheme))
        {
            authenticationScheme = TunnelAuthenticationDefaults.AuthenticationScheme;
        }
        var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationOptions>();
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

        if (!IsRegistered(builder.Services))
        {
            builder.AddScheme<TunnelAuthenticationOptions, TunnelAuthenticationHandler>(
                authenticationScheme, configure);
        }

        return builder;
    }

    public static AuthenticationBuilder TryAddTunnelAuthentication(
        this AuthenticationBuilder builder
        )
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }

        if (!IsRegistered(builder.Services))
        {
            builder.AddScheme<TunnelAuthenticationOptions, TunnelAuthenticationHandler>(
                TunnelAuthenticationDefaults.AuthenticationScheme, static (_) => { });
        }

        return builder;
    }

    public static IServiceCollection TryAddTunnelAuthentication(
        this IServiceCollection services
        )
    {
        if (services is null) { throw new ArgumentNullException(nameof(services)); }

        if (!IsRegistered(services))
        {
            services.AddAuthentication(static (_) => { })
                .AddScheme<TunnelAuthenticationOptions, TunnelAuthenticationHandler>(
                    TunnelAuthenticationDefaults.AuthenticationScheme,
                    static (_) => { });
        }

        return services;
    }

    private static bool IsRegistered(IServiceCollection services)
    {
        foreach (var serviceDescriptor in services)
        {
            if (typeof(TunnelAuthenticationHandler).Equals(serviceDescriptor.ImplementationType))
            {
                return true;
            }
        }
        return false;
    }
}
