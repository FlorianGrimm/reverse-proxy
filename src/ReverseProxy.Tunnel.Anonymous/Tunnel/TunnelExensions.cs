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
    /// <param name="builder">this</param>
    /// <returns>fluent this</returns>
    public static IReverseProxyBuilder AddTunnelServicesAnonymous(
        this IReverseProxyBuilder builder
        )
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationAnonymous.WebSocket>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationAnonymous.Http2>());
        return builder;
    }
}
