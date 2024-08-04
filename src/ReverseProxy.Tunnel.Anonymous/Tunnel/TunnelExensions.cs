// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelExtensionsAnonymous
{
    /// <summary>
    /// This adds anonymous tunnel authentication.
    /// This is really not recommended for production use.
    /// Please do use it - only for testing/trouble shooting purposes.
    /// This allows anyone to answer the request instead of your servers.
    /// You have been warned - DONT USE IT.
    /// </summary>
    /// <returns>fluent this</returns>
    public static IServiceCollection AddTunnelServicesAnonymous(
        this IServiceCollection services
        )
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationAnonymous>());
        return services;
    }

    //public static IReverseProxyBuilder AddTunnelServices(
    //    this IReverseProxyBuilder builder,
    //    TunnelServicesOptions? options = default
    //    )
    //{
    //    _ = builder.Services.AddTunnelServices(options);
    //    return builder;
    //}
}
