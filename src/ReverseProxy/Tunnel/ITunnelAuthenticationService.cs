// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// The tunnel authentication service.
/// </summary>
public interface ITunnelAuthenticationService
{
    /// <summary>
    /// The name of the authentication - Mode in the configuration.
    /// </summary>
    /// <returns>the unique name</returns>
    string GetAuthenticationMode();

    /// <summary>
    /// Get the transport
    /// </summary>
    /// <returns></returns>
    string GetTransport();

    /// <summary>
    /// Get the authentication service for the protocol.
    /// </summary>
    /// <param name="transport">transport</param>
    /// <returns>the related service.</returns>
    ITunnelAuthenticationService GetAuthenticationService(string transport);

    /// <summary>
    /// Configure the Kestrel server options for the tunnel.
    /// </summary>
    /// <param name="kestrelServerOptions">the options</param>
    void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions);

    /// <summary>
    /// Map custom Authentication endpoint for the tunnel.
    /// </summary>
    /// <param name="endpoints">the builder</param>
    /// <param name="conventionBuilder">the data endpoint</param>
    /// <param name="pattern">the url-pattern</param>
    void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern);

    /// <summary>
    /// Check if the tunnel request is authenticated.
    /// </summary>
    /// <param name="context">The request context</param>
    /// <param name="cluster">The cluster</param>
    /// <returns>true ok - false 401 response.</returns>
    ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster);
}

#if false
public interface ITunnelAuthenticationServiceForTransport
    : ITunnelAuthenticationService
{
    /// <summary>
    /// Get the transport
    /// </summary>
    /// <returns></returns>
    string GetTransport();
}
#endif

public interface IProxyRouteService {

    string GetTransport();

    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    void Map(
        IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configure
        );
}

public interface ITunnelAuthenticationConfigService
{
    IReadOnlyCollection<ITunnelAuthenticationService> GetTunnelAuthenticationServices(string transport);
    bool TryGetTunnelAuthenticationServices(string transport, string authenticationMode, [MaybeNullWhen(false)] out ITunnelAuthenticationService result);
}
