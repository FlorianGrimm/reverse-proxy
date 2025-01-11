// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelAuthenticationHandler<TOptions>
    : AuthenticationHandler<TOptions>
    where TOptions : TunnelAuthenticationOptions, new()
{
#if NET8_0_OR_GREATER
    protected TunnelAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }
#else
    protected TunnelAuthenticationHandler(IOptionsMonitor<TOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }
#endif

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!(Context.RequestServices.GetService<IProxyStateLookup>() is { } proxyConfigManager))
        {
            Logger.LogDebug("IProxyStateLookup not found. {RequestPath}", Context.Request.Path);
            return AuthenticateResult.NoResult();
        }
        if (!(Context.Request.RouteValues["clusterId"] is string clusterId))
        {
            Logger.LogDebug("clusterId not found. {RequestPath}", Context.Request.Path);
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

        if (!(proxyConfigManager.TryGetCluster(clusterId, out var cluster)
            && cluster.Model.Config is { } clusterConfig))
        {
            Logger.LogDebug("Cluster not found. {RequestPath} {clusterId}", Context.Request.Path, clusterId);
            return AuthenticateResult.NoResult();
        }

        var (authenticateResult, forwardScheme) = await tunnelAuthenticationMetadata.TunnelAuthentication.HandleAuthenticateAsync(
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

public class TunnelAuthenticationHandler : TunnelAuthenticationHandler<TunnelAuthenticationOptions>
{
#if NET8_0_OR_GREATER
    public TunnelAuthenticationHandler(IOptionsMonitor<TunnelAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }
#else
    public TunnelAuthenticationHandler(IOptionsMonitor<TunnelAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }
#endif
}

public class TunnelAuthenticationOptions : AuthenticationSchemeOptions { }

public static class TunnelAuthenticationOptionsExtensions
{
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

public interface ITunnelAuthentication
{
    ValueTask<TunnelAuthenticationResponse> HandleAuthenticateAsync(
        HttpContext context,
        ClusterConfig clusterConfig,
        string scheme,
        string claimsIssuer);
}

public record struct TunnelAuthenticationResponse(
    AuthenticateResult? AuthenticateResult,
    string? ForwardScheme)
{
    public TunnelAuthenticationResponse(
        ) : this(default, default)
    {
    }

    public TunnelAuthenticationResponse(
        AuthenticateResult AuthenticateResult
        ) : this(AuthenticateResult, default)
    {
    }

    public TunnelAuthenticationResponse(
        string ForwardScheme
        ) : this(default, ForwardScheme)
    {
    }
}

public sealed record TunnelAuthenticationMetadata(
    ITunnelAuthentication TunnelAuthentication);
