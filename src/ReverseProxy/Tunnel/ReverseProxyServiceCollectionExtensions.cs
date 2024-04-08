// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Tunnel;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Routing;
using Yarp.ReverseProxy.ServiceDiscovery;
using Yarp.ReverseProxy.Transforms.Builder;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions for <see cref="IServiceCollection"/>
/// used to register the ReverseProxy's components.
/// </summary>
public static partial class ReverseProxyServiceCollectionExtensions
{
    public static IServiceCollection AddTunnelServices(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IForwarderHttpClientTransportFactory, TunnelClientFactory>());
        return services;
    }

    public static IEndpointConventionBuilder MapHttp2Tunnel(this IEndpointRouteBuilder routes, string path)
    {
        var pattern = $"{path}/{{TunnelId}}";

        return routes.MapPost(pattern, async (HttpContext context) => await TunnelHandler.HandleHttp2Tunnel(context));
    }

    public static IEndpointConventionBuilder MapWebSocketTunnel(this IEndpointRouteBuilder routes, string path)
    {
        var pattern = $"{path}/{{TunnelId}}";
        var conventionBuilder = routes.Map(pattern, async (context) => await TunnelHandler.HandleWebSocketTunnel(context));

        // Make this endpoint do websockets automagically as middleware for this specific route
        conventionBuilder.Add(endpointBuilder =>
        {
            var sub = routes.CreateApplicationBuilder();
            sub.UseWebSockets().Run(endpointBuilder.RequestDelegate!);
            endpointBuilder.RequestDelegate = sub.Build();
        });

        return conventionBuilder;

    }
}
