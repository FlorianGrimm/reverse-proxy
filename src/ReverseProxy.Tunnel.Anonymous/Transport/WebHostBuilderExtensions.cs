// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Transport;

namespace Microsoft.AspNetCore.Builder;

public static class WebHostBuilderExtensions
{

    /// <summary>
    /// This adds anonymous tunnel authentication.
    /// This is really not recommended for production use.
    /// Please do use it - only for testing/trouble shooting purposes.
    /// This allows anyone to answer the request instead of your servers.
    /// You have been warned - DONT USE IT.
    /// </summary>
    public static IReverseProxyBuilder AddTunnelTransportAnonymous(
        this IReverseProxyBuilder builder
        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authenticator, TransportTunnelHttp2AuthenticatorAnonymous>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthenticator, TransportTunnelWebSocketAuthenticatorAnonymous>());
    
        return builder;
    }
}
