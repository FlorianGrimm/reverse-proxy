// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Limits;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Routing;
using Yarp.ReverseProxy.Tunnel;
using Yarp.ReverseProxy.Tunnel.Transport;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extension methods for <see cref="IEndpointRouteBuilder"/>
/// used to add Reverse Proxy to the ASP .NET Core request pipeline.
/// </summary>
public static partial class ReverseProxyIEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Adds Reverse Proxy routes to the route table using the default processing pipeline.
    /// </summary>
    public static ReverseProxyConventionBuilder MapReverseProxy(this IEndpointRouteBuilder endpoints)
    {
        return endpoints.MapReverseProxy(app =>
        {
            app.UseSessionAffinity();
            app.UseLoadBalancing();
            app.UsePassiveHealthChecks();
        });
    }

    /// <summary>
    /// Adds Reverse Proxy routes to the route table with the customized processing pipeline. The pipeline includes
    /// by default the initialization step and the final proxy step, but not LoadBalancingMiddleware or other intermediate components.
    /// </summary>
    public static ReverseProxyConventionBuilder MapReverseProxy(this IEndpointRouteBuilder endpoints, Action<IReverseProxyApplicationBuilder> configureApp)
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

        return GetOrCreateDataSource(endpoints).DefaultBuilder;
    }

    private static ProxyConfigManager GetOrCreateDataSource(IEndpointRouteBuilder endpoints)
    {
        var dataSource = endpoints.DataSources.OfType<ProxyConfigManager>().FirstOrDefault();
        if (dataSource is null)
        {
            dataSource = endpoints.ServiceProvider.GetRequiredService<ProxyConfigManager>();
            endpoints.DataSources.Add(dataSource);

            // Config validation is async but startup is sync. We want this to block so that A) any validation errors can prevent
            // the app from starting, and B) so that all the config is ready before the server starts accepting requests.
            // Reloads will be async.
            dataSource.InitialLoadAsync().GetAwaiter().GetResult();
        }

        return dataSource;
    }
}

public static partial class ReverseProxyIEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapReverseProxyTunnelFrontendToBackend(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var applicationServices = endpoints.ServiceProvider;
        var proxyTunnelConfigManager = applicationServices.GetRequiredService<ProxyTunnelConfigManager>();
        proxyTunnelConfigManager.Initialize(applicationServices);
        var tunnelFrontendToBackends = proxyTunnelConfigManager.GetTunnelFrontendToBackends();
        if (tunnelFrontendToBackends.Any())
        {
            var tunnelHandlerFactory = applicationServices.GetRequiredService<TunnelHandlerFactorySelector>();
            foreach (var tunnelFrontendToBackend in tunnelFrontendToBackends)
            {
                var tunnelHandler = tunnelHandlerFactory.Create(tunnelFrontendToBackend);
                if (tunnelHandler is not null)
                {
                    var endpointConventionBuilder = tunnelHandler.Map(endpoints);
                    endpointConventionBuilder
                        .WithMetadata(tunnelFrontendToBackend)
                        ;
                    proxyTunnelConfigManager.AddTunnelHandler(tunnelFrontendToBackend.TunnelId, tunnelHandler);
                }
            }
            endpoints.Map("/Tunnel/{protocol}/{tunnel}/{host}", (HttpContext context) =>
            {
                // TODO: proper logging
                context.RequestServices.GetRequiredService<ILogger<TunnelConnectionListenerProtocol>>().LogWarning("Tunnel is not defined {Path}", context.Request.Path);
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return Task.CompletedTask;
            });
        }
        return endpoints;
    }

}
