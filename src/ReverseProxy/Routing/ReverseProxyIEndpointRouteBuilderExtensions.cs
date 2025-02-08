// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Limits;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Routing;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extension methods for <see cref="IEndpointRouteBuilder"/>
/// used to add Reverse Proxy to the ASP .NET Core request pipeline.
/// </summary>
public static class ReverseProxyIEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Adds Reverse Proxy routes to the route table using the default processing pipeline.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    public static ReverseProxyConventionBuilder MapReverseProxy(
        this IEndpointRouteBuilder endpoints,
        Dictionary<string, Action<IEndpointConventionBuilder>>? configureEndpoints = default)
    {
        return endpoints.MapReverseProxy(app =>
        {
            app.UseSessionAffinity();
            app.UseLoadBalancing();
            app.UsePassiveHealthChecks();
        }, configureEndpoints);
    }

    /// <summary>
    /// Adds Reverse Proxy routes to the route table with the customized processing pipeline. The pipeline includes
    /// by default the initialization step and the final proxy step, but not LoadBalancingMiddleware or other intermediate components.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    public static ReverseProxyConventionBuilder MapReverseProxy(
        this IEndpointRouteBuilder endpoints,
        Action<IReverseProxyApplicationBuilder> configureApp,
        Dictionary<string, Action<IEndpointConventionBuilder>>? configureEndpoints = default
        )
    {
        if (endpoints is null)
        {
            throw new ArgumentNullException(nameof(endpoints));
        }
        if (configureApp is null)
        {
            throw new ArgumentNullException(nameof(configureApp));
        }

        var proxyAppBuilder = new ReverseProxyApplicationBuilder(endpoints.CreateApplicationBuilder());
        proxyAppBuilder.UseMiddleware<ProxyPipelineInitializerMiddleware>();
        configureApp(proxyAppBuilder);
        proxyAppBuilder.UseMiddleware<LimitsMiddleware>();
        proxyAppBuilder.UseMiddleware<ForwarderMiddleware>();
        var app = proxyAppBuilder.Build();

        var proxyEndpointFactory = endpoints.ServiceProvider.GetRequiredService<ProxyEndpointFactory>();
        proxyEndpointFactory.SetProxyPipeline(app);

        var proxyConfigManager = endpoints.DataSources.OfType<ProxyConfigManager>().FirstOrDefault();
        if (proxyConfigManager is null)
        {
            proxyConfigManager = endpoints.ServiceProvider.GetRequiredService<ProxyConfigManager>();
            endpoints.DataSources.Add(proxyConfigManager);

            // Config validation is async but startup is sync. We want this to block so that A) any validation errors can prevent
            // the app from starting, and B) so that all the config is ready before the server starts accepting requests.
            // Reloads will be async.
            proxyConfigManager.InitialLoadAsync().GetAwaiter().GetResult();

            // The (memory) config can change - so checking the config does not work.
            // Testing if .AddTunnelServices() was called will do it
            var areTunnelServicesEnabled = endpoints.ServiceProvider.GetService<TunnelConnectionChannelManager>() != null;
            if (areTunnelServicesEnabled)
            {
                endpoints.MapTunnels(configureEndpoints);
            }
        }
        return proxyConfigManager.DefaultBuilder;
    }
}
