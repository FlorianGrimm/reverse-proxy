// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Transport;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions for <see cref="IServiceCollection"/>
/// used to register the ReverseProxy's components.
/// </summary>
public static class ReverseProxyServiceCollectionExtensions
{

    public static IReverseProxyBuilder AddAuthorizationTransportTransformProvider(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = default,
        Action<AuthorizationTransportOptions>? configure = default)
    {
        var optionsBuilder = builder.Services.AddOptions<AuthorizationTransportOptions>();
        if (configuration is not null || configure is not null)
        {
            optionsBuilder.Configure((options) => {
                if (configuration is not null)
                {
                    options.Bind(configuration);
                }
                if (configure is not null) {
                    configure(options);
                }
            });
        }

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransformProvider, AuthorizationTransportTransformProvider>());
        return builder;
    }
}
