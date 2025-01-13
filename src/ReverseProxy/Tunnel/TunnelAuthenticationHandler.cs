// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// Handles tunnel authentication for the reverse proxy.
/// </summary>
/// <typeparam name="TOptions">The type of authentication options.</typeparam>
public class TunnelAuthenticationHandler<TOptions>
    : AuthenticationHandler<TOptions>
    , Microsoft.AspNetCore.Authentication.IAuthenticationRequestHandler
    where TOptions : TunnelAuthenticationOptions, new()
{
#if NET8_0_OR_GREATER
    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationHandler{TOptions}"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    protected TunnelAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

#else
    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationHandler{TOptions}"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="clock">The system clock.</param>
    protected TunnelAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }
#endif

    /// <summary>
    /// Gets a value that determines if the request should stop being processed.
    /// <para>
    /// This feature is supported by the Authentication middleware
    /// which does not invoke any subsequent <see cref="IAuthenticationHandler"/> or middleware configured in the request pipeline
    /// if the handler returns <see langword="true" />.
    /// </para>
    /// </summary>
    /// <returns><see langword="true" /> if request processing should stop.</returns>
    public async Task<bool> HandleRequestAsync()
    {
        if (!(Context.RequestServices.GetService<IProxyStateLookup>() is { } proxyConfigManager))
        {
            Logger.LogDebug("IProxyStateLookup not found. {RequestPath}", Context.Request.Path);
            return false;
        }

        if (!(Context.GetEndpoint() is { } endpoint))
        {
            Logger.LogDebug("Endpoint not found. {RequestPath}", Context.Request.Path);
            return false;
        }

        if (!(endpoint.Metadata.GetMetadata<TunnelAuthenticationMetadata>() is { } tunnelAuthenticationMetadata))
        {
            Logger.LogDebug("TunnelAuthenticationMetadata not found. {RequestPath}", Context.Request.Path);
            return false;
        }

        if (!(Context.Request.RouteValues["clusterId"] is string clusterId))
        {
            Logger.LogDebug("clusterId not found. {RequestPath}", Context.Request.Path);
            return false;
        }

        if (!(proxyConfigManager.TryGetCluster(clusterId, out var cluster)
            && cluster.Model.Config is { } clusterConfig))
        {
            Logger.LogDebug("Cluster not found. {RequestPath} {clusterId}", Context.Request.Path, clusterId);
            return false;
        }


        var (authenticateResult, forwardScheme) = await tunnelAuthenticationMetadata.TunnelAuthentication.HandleTunnelAuthenticateAsync(
            Context, clusterConfig, Scheme.Name, ClaimsIssuer);

        if (authenticateResult is { })
        {
            return false;
        }
        /*

        // TODO: TEST
        if (forwardScheme is { Length: > 0 }
            && ResolveTarget(forwardScheme) is { } target
            && Context.RequestServices.GetService<IAuthenticationHandlerProvider>() is { } authenticationHandlerProvider
            && (await authenticationHandlerProvider.GetHandlerAsync(Context, target)) is { } handler
            )
        {
            return await handler.AuthenticateAsync();
        }

        return false;         
         */
        await Task.CompletedTask;
        return false;
    }

    /// <summary>
    /// Handles the authentication process.
    /// </summary>
    /// <returns>The authentication result.</returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!(Context.RequestServices.GetService<IProxyStateLookup>() is { } proxyConfigManager))
        {
            Logger.LogDebug("IProxyStateLookup not found. {RequestPath}", Context.Request.Path);
            return AuthenticateResult.NoResult();
        }

        if (!(Context.GetEndpoint() is { } endpoint))
        {
            Logger.LogDebug("Endpoint not found. {RequestPath}", Context.Request.Path);
            return AuthenticateResult.NoResult();
        }

        if (!(endpoint.Metadata.GetMetadata<TunnelAuthenticationMetadata>() is { } tunnelAuthenticationMetadata))
        {
            Logger.LogDebug("TunnelAuthenticationMetadata not found. {RequestPath}", Context.Request.Path);
            return AuthenticateResult.NoResult();
        }

        if (!(Context.Request.RouteValues["clusterId"] is string clusterId))
        {
            Logger.LogDebug("clusterId not found. {RequestPath}", Context.Request.Path);
            return AuthenticateResult.NoResult();
        }

        if (!(proxyConfigManager.TryGetCluster(clusterId, out var cluster)
            && cluster.Model.Config is { } clusterConfig))
        {
            Logger.LogDebug("Cluster not found. {RequestPath} {clusterId}", Context.Request.Path, clusterId);
            return AuthenticateResult.NoResult();
        }

        var (authenticateResult, forwardScheme) = await tunnelAuthenticationMetadata.TunnelAuthentication.HandleTunnelAuthenticateAsync(
            Context, clusterConfig, Scheme.Name, ClaimsIssuer);

        if (authenticateResult is { })
        {
            return authenticateResult;
        }

        // TODO: TEST
        if (forwardScheme is { Length: > 0 }
            && ResolveTarget(forwardScheme) is { } target
            && Context.RequestServices.GetService<IAuthenticationHandlerProvider>() is { } authenticationHandlerProvider
            && (await authenticationHandlerProvider.GetHandlerAsync(Context, target)) is { } handler
            )
        {
            return await handler.AuthenticateAsync();
        }

        return AuthenticateResult.NoResult();
    }
}

/// <summary>
/// Default implementation of <see cref="TunnelAuthenticationHandler{TOptions}"/>.
/// </summary>
public class TunnelAuthenticationHandler : TunnelAuthenticationHandler<TunnelAuthenticationOptions>
{
#if NET8_0_OR_GREATER
    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public TunnelAuthenticationHandler(IOptionsMonitor<TunnelAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }
#else
    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The options monitor.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="clock">The system clock.</param>
    public TunnelAuthenticationHandler(IOptionsMonitor<TunnelAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }
#endif
}

/// <summary>
/// Options for tunnel authentication.
/// </summary>
public class TunnelAuthenticationOptions : AuthenticationSchemeOptions { }

/// <summary>
/// Extension methods for <see cref="TunnelAuthenticationOptions"/>.
/// </summary>
public static class TunnelAuthenticationOptionsExtensions
{
    /// <summary>
    /// Binds the configuration to the <see cref="TunnelAuthenticationOptions"/>.
    /// </summary>
    /// <param name="options">The tunnel authentication options.</param>
    /// <param name="configuration">The configuration.</param>
    public static void Bind(
        this TunnelAuthenticationOptions options,
        IConfiguration configuration)
    {
        if (configuration.GetSection(nameof(AuthenticationSchemeOptions.ClaimsIssuer)).Value
            is { Length: > 0 } valueClaimsIssuer)
        {
            options.ClaimsIssuer = valueClaimsIssuer;
        }
    }
}

/// <summary>
/// Interface for handling tunnel authentication.
/// 
/// </summary>
public interface ITunnelAuthenticationHandler
{
    /// <summary>
    /// Handles the tunnel authentication process.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="clusterConfig">The cluster configuration.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="claimsIssuer">The claims issuer.</param>
    /// <returns>The tunnel authentication response.</returns>
    ValueTask<TunnelAuthenticationResponse> HandleTunnelAuthenticateAsync(
        HttpContext context,
        ClusterConfig clusterConfig,
        string scheme,
        string claimsIssuer);
}


/// <summary>
/// Microsoft.AspNetCore.Authentication.IAuthenticationRequestHandler
/// </summary>
public interface ITunnelAuthenticationRequestHandler : ITunnelAuthenticationHandler
{
    /// <summary>
    /// Handles the tunnel authentication process.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="clusterConfig">The cluster configuration.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="claimsIssuer">The claims issuer.</param>
    /// <returns>The tunnel authentication response.</returns>
    ValueTask<BadHttpRequestException> HandleTunnelAuthenticateRequestAsync(
        HttpContext context,
        ClusterConfig clusterConfig,
        string scheme,
        string claimsIssuer);
}

/// <summary>
/// Represents the response from tunnel authentication.
/// </summary>
/// <param name="AuthenticateResult">The authentication result.</param>
/// <param name="ForwardScheme">The forward scheme.</param>
public record struct TunnelAuthenticationResponse(
    AuthenticateResult? AuthenticateResult,
    string? ForwardScheme)
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationResponse"/> struct.
    /// </summary>
    public TunnelAuthenticationResponse(
        ) : this(default, default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationResponse"/> struct with an authentication result.
    /// </summary>
    /// <param name="AuthenticateResult">The authentication result.</param>
    public TunnelAuthenticationResponse(
        AuthenticateResult AuthenticateResult
        ) : this(AuthenticateResult, default)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TunnelAuthenticationResponse"/> struct with a forward scheme.
    /// </summary>
    /// <param name="ForwardScheme">The forward scheme.</param>
    public TunnelAuthenticationResponse(
        string ForwardScheme
        ) : this(default, ForwardScheme)
    {
    }
}

/// <summary>
/// Metadata for tunnel authentication.
/// </summary>
/// <param name="TunnelAuthentication">The tunnel authentication handler.</param>
public sealed record TunnelAuthenticationMetadata(
    ITunnelAuthenticationHandler TunnelAuthentication);

