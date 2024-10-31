// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Builder;
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
        Action<AuthorizationTransportOptions>? configureOptions = default)
    {
        var optionsBuilder = builder.Services.AddOptions<AuthorizationTransportOptions>();
        if (configureOptions is not null)
        {
            optionsBuilder.Configure(configureOptions);
        }

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransformProvider, AuthorizationTransportTransformProvider>());
        return builder;
    }
}
