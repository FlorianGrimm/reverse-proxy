using System.Diagnostics.CodeAnalysis;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Tree;

namespace Yarp.ReverseProxy.Tunnel;

//public interface ITunnelAuthenticationScheme
//{
//    string AuthenticationScheme { get; }
//}

public record TunnelAuthenticationScheme(string AuthenticationScheme)
{
}

public static class TunnelAuthenticationSchemeExtensions
{
    public static bool TryGetTunnelAuthenticationScheme(
        this Endpoint? endpoint,
        [MaybeNullWhen(false)] out string authenticationScheme)
    {
        if (endpoint?.Metadata.GetMetadata<TunnelAuthenticationScheme>()?.AuthenticationScheme is { Length: > 0 } scheme)
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
        if (endpoint?.Metadata.GetMetadata<TunnelAuthenticationScheme>()?.AuthenticationScheme is { Length: > 0 } scheme)
        {
            return scheme;
        }
        else
        {
            return defaultAuthenticationScheme;
        }
    }
}
