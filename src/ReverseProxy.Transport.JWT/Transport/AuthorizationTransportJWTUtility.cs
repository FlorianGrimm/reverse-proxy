using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Security.Claims;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Utility class for creating JWT tokens and claims identities.
/// </summary>
public static class AuthorizationTransportJWTUtility {
    /// <summary>
    /// Creates a <see cref="ClaimsIdentity"/> for the JWT token from the inbound user.
    /// </summary>
    /// <param name="inboundUser">The inbound user principal.</param>
    /// <param name="options">The options for creating the JWT token.</param>
    /// <returns>A <see cref="ClaimsIdentity"/> for the JWT token, or null if the inbound user is null.</returns>
    [return: NotNullIfNotNull(nameof(inboundUser))]
    public static ClaimsIdentity? CreateJWTClaimsIdentity(
        ClaimsPrincipal? inboundUser,
        AuthorizationTransportOptions options) {
        if (inboundUser is null) { return default; }

        var outboundClaimsIdentity = new ClaimsIdentity();

        var includeAll = options.IncludeClaimType.Contains("ALL")
            || ((options.ExcludeClaimType.Count == 0)
                && (options.TransformClaimType.Count == 0)
                && (options.IncludeClaimType.Count == 0)
                );
        foreach (var inboundClaim in inboundUser.Claims) {
            if (options.ExcludeClaimType.Contains(inboundClaim.Type)) {
                continue;
            }

            if (options.TransformClaimType.TryGetValue(inboundClaim.Type, out var destinationClaimType)) {
                var outboundClaim = new Claim(type: destinationClaimType, value: inboundClaim.Value,
                    valueType: inboundClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            } else if (includeAll || options.IncludeClaimType.Contains(inboundClaim.Type)) {
                var outboundClaim = new Claim(type: inboundClaim.Type, value: inboundClaim.Value,
                    valueType: inboundClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            }
        }

        return outboundClaimsIdentity;
    }

    /// <summary>
    /// Creates a JWT token from the specified claims identity.
    /// </summary>
    /// <param name="outboundClaimsIdentity">The claims identity for the JWT token.</param>
    /// <param name="signingCredentials">The signing credentials for the JWT token.</param>
    /// <param name="options">The options for creating the JWT token.</param>
    /// <returns>The created JWT token.</returns>
    public static string CreateJWTToken(
        ClaimsIdentity outboundClaimsIdentity,
        SigningCredentials signingCredentials,
        AuthorizationTransportOptions options) {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor {
            Issuer = options.Issuer,
            Audience = options.Audience,
            IssuedAt = now,
            NotBefore = now.Add(options.AdjustNotBefore),
            Expires = now.Add(options.AdjustExpires),
            Subject = outboundClaimsIdentity,
            SigningCredentials = signingCredentials
        };

        Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler jsonWebTokenHandler = new();
        var jwtToken = jsonWebTokenHandler.CreateToken(descriptor);
        return jwtToken;
    }
}
