using System;
using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Http;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// Represents metadata for tunnel authentication scheme.
/// </summary>
/// <param name="AuthenticationScheme">The authentication scheme.</param>
public sealed record TunnelAuthenticationSchemeMetadata(string AuthenticationScheme);

/// <summary>
/// Provides extension methods for <see cref="TunnelAuthenticationSchemeMetadata"/>.
/// </summary>
public static class TunnelAuthenticationSchemeExtensions
{
    /// <summary>
    /// Tries to get the tunnel authentication scheme from the specified endpoint.
    /// </summary>
    /// <param name="endpoint">The endpoint to get the authentication scheme from.</param>
    /// <param name="authenticationScheme">When this method returns, contains the authentication scheme if found; otherwise, null.</param>
    /// <returns><c>true</c> if the authentication scheme was found; otherwise, <c>false</c>.</returns>
    public static bool TryGetTunnelAuthenticationScheme(
        this Endpoint? endpoint,
        [MaybeNullWhen(false)] out string authenticationScheme)
    {
        if (endpoint?
            .Metadata
            .GetMetadata<TunnelAuthenticationSchemeMetadata>()?
            .AuthenticationScheme is { Length: > 0 } scheme)
        {
            authenticationScheme = scheme;
            return true;
        }
        else
        {
            authenticationScheme = default;
            return false;
        }
    }

    /// <summary>
    /// Creates a function that selects the forward default authentication scheme.
    /// </summary>
    /// <param name="defaultAuthenticationScheme">The default authentication scheme to use if none is found in the endpoint metadata.</param>
    /// <returns>A function that selects the forward default authentication scheme.</returns>
    /// <example>
    ///    builder.Services.AddAuthentication("Default")
    ///        .AddXYZ()
    ///        .AddPolicyScheme(
    ///            authenticationScheme: "Default",
    ///            displayName: "Default",
    ///            configureOptions: static (options) =>
    ///            {
    ///                options.ForwardDefaultSelector = TunnelAuthenticationSchemeExtensions
    ///                    .CreateForwardDefaultSelector(XYZDefaults.AuthenticationScheme);
    ///            });
    /// </example>
    public static Func<HttpContext, string?> CreateForwardDefaultSelector(
        string defaultAuthenticationScheme
        )
    {
        return ForwardDefaultSelector;

        string? ForwardDefaultSelector(HttpContext httpContext)
        {
            if (httpContext.GetEndpoint()?
                .Metadata
                .GetMetadata<TunnelAuthenticationSchemeMetadata>()?
                .AuthenticationScheme is { Length: > 0 } scheme)
            {
                return scheme;
            }
            else
            {
                return defaultAuthenticationScheme;
            }
        }
    }
}
