using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Gets or sets the adjustment to the 'Not Before' time for the JWT token.
/// This adjustment is applied to account for clock skew between systems.
/// Options for configuring authorization transport.
/// </summary>
public class AuthorizationTransportOptions : IEquatable<AuthorizationTransportOptions>
{
    /// <summary>
    /// Gets or sets a value indicating whether the authorization transport is enabled for all clusters.
    /// </summary>
    /// <remarks>
    /// if false, the authorization transport is enabled only for clusters that have the metadata flag "EnableAuthenticationTransportTransform" set to true.
    /// </remarks>
    public bool EnableForAllCluster { get; set; }

    /// <summary>
    /// Prevents the Authorization header from being modified if it already contains a Bearer token.
    /// </summary>
    public bool DoNotModifyAuthorizationIfBearer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether authenticate headers should be removed.
    /// If false nothing is done.
    /// If true and DoNotModifyAuthorizationIfBearer is true and a Bearer token is found, the WWW-Authenticate header is removed.
    /// If true and request is authenticated, the Authorization header is replaced and the WWW-Authenticate header should be removed from the request.
    /// If true and request is not authenticated, the Authorization and the WWW-Authenticate header is removed.
    /// </summary>
    public bool RemoveHeaderAuthenticate { get; set; } = true;

    /// <summary>
    /// Gets or sets the scheme to be used for authorization.
    /// </summary>
    public string? Scheme { get; set; }

    public Func<HttpContext, string?>? AuthenticationSchemeSelector {get;set;}

    public Func<ResponseTransformContext, string?>? ChallengeSchemeSelector {get;set;}

    /// <summary>
    /// Gets or sets the claim types to be excluded.
    /// </summary>
    public HashSet<string> ExcludeClaimType { get; set; } = new HashSet<string>();

    /// <summary>
    /// Gets or sets the claim types to be transformed.
    /// </summary>
    public Dictionary<string, string> TransformClaimType { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// Gets or sets the claim types to be included.
    /// </summary>
    public HashSet<string> IncludeClaimType { get; set; } = new HashSet<string>();

    /// <summary>
    /// Gets or sets the issuer of the token.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the audience of the token.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Gets or sets the authentication type.
    /// </summary>
    public string? AuthenticationType { get; set; }

    /// <summary>
    /// Gets or sets the adjustment to the 'Not Before' time for the JWT token.
    /// This adjustment is applied to account for clock skew between systems.
    /// The default value is -30 seconds.
    /// </summary>
    public TimeSpan AdjustNotBefore { get; set; } = TimeSpan.FromSeconds(-30);

    /// <summary>
    /// Gets or sets the adjustment to the 'Expires' time for the JWT token.
    /// This adjustment is applied to account for clock skew between systems.
    /// The default value is +30 seconds.
    /// </summary>
    public TimeSpan AdjustExpires { get; set; } = TimeSpan.FromSeconds(+30);

    /// <summary>
    /// Gets or sets the secret for a SymmetricSecurityKey.
    /// </summary>
    public string? SigningKeySecret { get; set; }

    /// <summary>
    /// Gets or sets the configuration for the signing certificate.
    /// </summary>
    public string? SigningCertificate { get; set; }

    /// <summary>
    /// Gets or sets the function to create the SigningCredentials (and SigningKey).
    /// </summary>
    public Func<SigningCredentials>? CreateSigningCredential { get; set; }

    /// <summary>
    /// Gets or sets the algorithm used for signing the token. Default is RsaSha256
    /// </summary>
    public string Algorithm { get; set; } = SecurityAlgorithms.RsaSha256;

    /// <summary>
    /// Determines if the authorization transport is enabled for the cluster.
    /// EnableForAllCluster is true
    /// - or -
    /// Metadata.EnableAuthenticationTransportTransform is true
    /// </summary>
    /// <param name="cluster">the cluster</param>
    /// <returns></returns>
    public bool IsEnabled(ClusterConfig cluster)
    {
        if (SigningCertificate is null)
        {
            return false;
        }

        if (EnableForAllCluster)
        {
            return true;
        }
        else
        {
            return (
                cluster is { Metadata: { } metadata }
                && metadata.TryGetValue("EnableAuthenticationTransportTransform", out var flag)
                && !string.IsNullOrEmpty(flag)
                && bool.TryParse(flag, out var flagValue)
                && flagValue
            );
        }
    }

    public override bool Equals(object? obj)
    {
        return Equals(obj as AuthorizationTransportOptions);
    }

    public bool Equals(AuthorizationTransportOptions? other)
    {
        if (other is null)
        {
            return false;
        }
        if (ReferenceEquals(this, other))
        {
            return true;
        }
        return ((EnableForAllCluster == other.EnableForAllCluster)
            && (DoNotModifyAuthorizationIfBearer == other.DoNotModifyAuthorizationIfBearer)
            && (RemoveHeaderAuthenticate == other.RemoveHeaderAuthenticate)
            && (string.Equals(Scheme, other.Scheme, StringComparison.Ordinal))
            && (ExcludeClaimType.SetEquals(other.ExcludeClaimType))
            && (TransformClaimType.SequenceEqual(other.TransformClaimType))
            && (IncludeClaimType.SetEquals(other.IncludeClaimType))
            && (string.Equals(Issuer, other.Issuer, StringComparison.Ordinal))
            && (string.Equals(Audience, other.Audience, StringComparison.Ordinal))
            && (string.Equals(AuthenticationType, other.AuthenticationType))
            && (AdjustNotBefore == other.AdjustNotBefore)
            && (AdjustExpires == other.AdjustExpires)
            && (string.Equals(SigningCertificate, other.SigningCertificate))
            && (string.Equals(SigningKeySecret, other.SigningKeySecret))
            && (string.Equals(Algorithm, other.Algorithm))
            );
    }

    public override int GetHashCode()
    {
        HashCode result = new();
        result.Add(EnableForAllCluster);
        result.Add(DoNotModifyAuthorizationIfBearer);
        result.Add(RemoveHeaderAuthenticate);
        result.Add(Scheme, StringComparer.Ordinal);
        foreach (var item in ExcludeClaimType) { result.Add(item); }
        foreach (var item in TransformClaimType) { result.Add(item); }
        foreach (var item in IncludeClaimType) { result.Add(item); }
        result.Add(Issuer, StringComparer.Ordinal);
        result.Add(Audience, StringComparer.Ordinal);
        result.Add(AuthenticationType, StringComparer.Ordinal);
        result.Add(AdjustNotBefore);
        result.Add(AdjustExpires);
        result.Add(SigningCertificate);
        result.Add(SigningKeySecret);
        result.Add(Algorithm, StringComparer.Ordinal);
        return result.ToHashCode();
    }
}
