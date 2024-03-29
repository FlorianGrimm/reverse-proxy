// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Configuration.ConfigProvider;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Routing;
using Yarp.ReverseProxy.ServiceDiscovery;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Microsoft.Extensions.DependencyInjection;

// TODO move to src\ReverseProxy\Management\ReverseProxyServiceCollectionExtensions.cs
public static partial class ReverseProxyServiceCollectionExtensions
{
    public static IServiceCollection AddTunnelServices(this IServiceCollection services){
        return services;
    }
}
