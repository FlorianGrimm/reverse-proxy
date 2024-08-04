// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelExtensions
{
    /// <summary>
    /// Adds the services required for tunneling.
    /// </summary>
    /// <param name="services">this</param>
    /// <returns>fluent this</returns>
    public static IServiceCollection AddTunnelServicesNegotiate(
        this IServiceCollection services
        )
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationNegotiate>());

        services.AddAuthorization(
            options =>
            {
                TunnelAuthenticationNegotiate.ConfigureAuthorizationPolicy(options);
            });

        return services;
    }
}
