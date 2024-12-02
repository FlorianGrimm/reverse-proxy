// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelExtensions
{
    /// <summary>
    /// Adds the services required for tunneling.
    /// </summary>
    /// <param name="builder">this</param>
    /// <returns>fluent this</returns>
    public static IReverseProxyBuilder AddTunnelServicesNegotiate(
        this IReverseProxyBuilder builder
        )
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelNegotiateHttp2>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelNegotiateWebSocket>());

        builder.Services.AddAuthorization(
            options =>
            {
                TunnelNegotiateBase.ConfigureAuthorizationPolicy(options);
            });

        return builder;
    }
}
