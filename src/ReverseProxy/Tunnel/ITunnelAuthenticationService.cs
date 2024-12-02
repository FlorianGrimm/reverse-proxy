// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
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
    /// <returns>The transport of this implementation</returns>
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

/// <summary>
/// Allows the tunnel to add the endpoints
/// </summary>
public interface ITunnelRouteService {
    /// <summary>
    /// Get the transport
    /// </summary>
    /// <returns>The transport of this implementation</returns>
    string GetTransport();

    /// <summary>
    /// Create new Endpoints for the transport.
    /// </summary>
    /// <param name="endpoints">the builder</param>
    /// <param name="configure">configure the endpoint.</param>
    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute("Map")]
    void Map(
        IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configure
        );
}

/// <summary>
/// Provides configuration services for tunnel authentication.
/// </summary>
public interface ITunnelAuthenticationConfigService
{
    /// <summary>
    /// Gets a collection of tunnel authentication services for the specified transport.
    /// </summary>
    /// <param name="transport">The transport for which to get the authentication services.</param>
    /// <returns>A read-only collection of tunnel authentication services.</returns>
    IReadOnlyCollection<ITunnelAuthenticationService> GetTunnelAuthenticationServices(string transport);

    /// <summary>
    /// Tries to get a tunnel authentication service for the specified transport and authentication mode.
    /// </summary>
    /// <param name="transport">The transport for which to get the authentication service.</param>
    /// <param name="authenticationMode">The authentication mode for which to get the authentication service.</param>
    /// <param name="result">When this method returns, contains the tunnel authentication service if found; otherwise, null.</param>
    /// <returns><c>true</c> if a tunnel authentication service was found; otherwise, <c>false</c>.</returns>
    bool TryGetTunnelAuthenticationServices(string transport, string authenticationMode, [MaybeNullWhen(false)] out ITunnelAuthenticationService result);
}

public interface ITunnelAuthentication
{
    ValueTask<AuthenticateResult> HandleAuthenticateAsync(HttpContext context, string scheme, string claimsIssuer);
}

public sealed record TunnelAuthenticationFeature(ITunnelAuthentication TunnelAuthentication);
