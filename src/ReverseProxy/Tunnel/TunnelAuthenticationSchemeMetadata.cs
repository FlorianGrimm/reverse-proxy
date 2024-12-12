using System;
using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Http;

namespace Yarp.ReverseProxy.Tunnel;

public sealed record TunnelAuthenticationSchemeMetadata(string AuthenticationScheme);

public static class TunnelAuthenticationSchemeExtensions
{
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

    public static string GetTunnelAuthenticationSchemeOrDefault(
        this Endpoint? endpoint,
        string defaultAuthenticationScheme)
    {
        if (endpoint?
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

    public static Func<HttpContext, string?> CreateForwardDefaultSelector(
        string defaultAuthenticationScheme
        )
    {
        return ForwardDefaultSelector;

        string? ForwardDefaultSelector(HttpContext context)
        {
            if (context.GetEndpoint()?
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
