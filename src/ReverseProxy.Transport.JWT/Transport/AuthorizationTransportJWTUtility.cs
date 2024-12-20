using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public sealed class AuthorizationTransportJWTUtilityService
{
    private readonly AuthorizationTransportSigningCertificate _signingCertificate;
    private AuthorizationTransportOptions _options;

    public AuthorizationTransportJWTUtilityService(
        ICertificateManager certificateManager,
        IOptionsMonitor<AuthorizationTransportOptions> options)
    {
        _signingCertificate = new AuthorizationTransportSigningCertificate(
            certificateManager,
            options);
        options.OnChange(OptionsOnChange);
        _options = options.CurrentValue;
    }

    private void OptionsOnChange(AuthorizationTransportOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }
        _options = options;
    }

    [return: NotNullIfNotNull(nameof(inboundUser))]
    public ClaimsIdentity? CreateJWTClaimsIdentity(
        ClaimsPrincipal? inboundUser)
        => AuthorizationTransportJWTUtility.CreateJWTClaimsIdentity(inboundUser, _options);

    public string CreateJWTToken(ClaimsIdentity outboundClaimsIdentity)
    {
        using (var shareSigningCredentials = _signingCertificate.GetSigningCredentials()) {
            if (!(shareSigningCredentials?.Value is { } certificate))
            {
                throw new InvalidOperationException("No signing credentials available.");
            }
            return AuthorizationTransportJWTUtility.CreateJWTToken(outboundClaimsIdentity, certificate, _options);
        }
    }
}

public static class AuthorizationTransportJWTUtility
{
    [return: NotNullIfNotNull(nameof(inboundUser))]
    public static ClaimsIdentity? CreateJWTClaimsIdentity(
        ClaimsPrincipal? inboundUser,
        AuthorizationTransportOptions options)
    {
        if (inboundUser is null) { return default; }

        var outboundClaimsIdentity = new ClaimsIdentity();

        var includeAll = options.IncludeClaimType.Contains("ALL")
            || ((options.ExcludeClaimType.Count == 0)
                && (options.TransformClaimType.Count == 0)
                && (options.IncludeClaimType.Count == 0)
                );
        foreach (var inboundClaim in inboundUser.Claims)
        {
            if (options.ExcludeClaimType.Contains(inboundClaim.Type))
            {
                continue;
            }

            if (options.TransformClaimType.TryGetValue(inboundClaim.Type, out var destinationClaimType))
            {
                var outboundClaim = new Claim(type: destinationClaimType, value: inboundClaim.Value,
                    valueType: inboundClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            }
            else if (includeAll || options.IncludeClaimType.Contains(inboundClaim.Type))
            {
                var outboundClaim = new Claim(type: inboundClaim.Type, value: inboundClaim.Value,
                    valueType: inboundClaim.ValueType);
                outboundClaimsIdentity.AddClaim(outboundClaim);
            }
        }

        return outboundClaimsIdentity;
    }

    public static string CreateJWTToken(
        ClaimsIdentity outboundClaimsIdentity,
        SigningCredentials signingCredentials,
        AuthorizationTransportOptions options)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
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
