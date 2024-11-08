using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Configuration;
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
    /// Gets or sets the configuration for the signing certificate.
    /// </summary>
    public CertificateConfig? SigningCertificateConfig { get; set; }

    /// <summary>
    /// Gets or sets the configuration for the signing certificates.
    /// </summary>
    public List<CertificateConfig> SigningCertificateConfigs { get; set; } = new();

    /// <summary>
    /// Gets or sets the collection of signing certificates.
    /// </summary>
    public X509Certificate2Collection? SigningCertificateCollection { get; set; }

    /// <summary>
    /// Gets or sets the function to create the signing key.
    /// </summary>
    public Func<SigningCredentials>? CreateSigningKey { get; set; }

    /// <summary>
    /// Gets or sets the algorithm used for signing the token. Default is RsaSha256
    /// </summary>
    public string Algorithm { get; set; } = SecurityAlgorithms.RsaSha256;

    /// <summary>
    /// Gets or sets the certificate requirement.
    /// </summary>
    public CertificateRequirement CertificateRequirement { get; set; } = new CertificateRequirement();

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
        if (SigningCertificateConfig is null)
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

    /// <summary>
    /// Binds the configuration to the options.
    /// </summary>
    /// <param name="configuration">configuration</param>
    public void Bind(IConfiguration configuration)
    {
        if (bool.TryParse(configuration[nameof(EnableForAllCluster)], out var valueEnableForAllCluster))
        {
            EnableForAllCluster = valueEnableForAllCluster;
        }
        if (bool.TryParse(configuration[nameof(DoNotModifyAuthorizationIfBearer)], out var valueDoNotModifyAuthorizationIfBearer))
        {
            DoNotModifyAuthorizationIfBearer = valueDoNotModifyAuthorizationIfBearer;
        }
        if (bool.TryParse(configuration[nameof(RemoveHeaderAuthenticate)], out var valueRemoveHeaderAuthenticate))
        {
            RemoveHeaderAuthenticate = valueRemoveHeaderAuthenticate;
        }
        if (configuration[nameof(Scheme)] is { Length: > 0 } valueScheme)
        {
            Scheme = valueScheme;
        }
        foreach (var valueExcludeClaimType in configuration.GetSection(nameof(ExcludeClaimType)).GetChildren())
        {
            if (valueExcludeClaimType.Value is { Length: > 0 } value)
            {
                ExcludeClaimType.Add(value);
            }
        }
        foreach (var valueTransformClaimType in configuration.GetSection(nameof(TransformClaimType)).GetChildren())
        {
            if (valueTransformClaimType.Key is { Length: > 0 } key
                && valueTransformClaimType.Value is { Length: > 0 } value)
            {
                TransformClaimType.Add(key, value);
            }
        }
        foreach (var valueIncludeClaimType in configuration.GetSection(nameof(IncludeClaimType)).GetChildren())
        {
            if (valueIncludeClaimType.Value is { Length: > 0 } value)
            {
                IncludeClaimType.Add(value);
            }
        }
        if (configuration[nameof(Issuer)] is { Length: > 0 } valueIssuer)
        {
            Issuer = valueIssuer;
        }
        if (configuration[nameof(Audience)] is { Length: > 0 } valueAudience)
        {
            Audience = valueAudience;
        }
        if (configuration[nameof(AuthenticationType)] is { Length: > 0 } valueAuthenticationType)
        {
            AuthenticationType = valueAuthenticationType;
        }
        if (TimeSpan.TryParse(configuration[nameof(AdjustNotBefore)], out var valueAdjustNotBefore))
        {
            AdjustNotBefore = valueAdjustNotBefore;
        }
        if (TimeSpan.TryParse(configuration[nameof(AdjustExpires)], out var valueAdjustExpires))
        {
            AdjustExpires = valueAdjustExpires;
        }

        if (CertificateConfigUtility.ConvertCertificateConfig(configuration.GetSection(nameof(SigningCertificateConfig)))
            is { } valueSigningCertificateConfig)
        {
            SigningCertificateConfig = valueSigningCertificateConfig;
        }

        SigningCertificateConfigs = CertificateConfigUtility.ConvertCertificateConfigs(
            configuration.GetSection(nameof(SigningCertificateConfigs)),
            SigningCertificateConfigs);

        if (configuration[nameof(Algorithm)] is { Length: > 0 } valueAlgorithm)
        {
            // SecurityAlgorithms.RsaSha256 = "RS256";
            Algorithm = valueAlgorithm;
        }
        var sectionCertificateRequirement = configuration.GetSection(nameof(CertificateRequirement));
        if (sectionCertificateRequirement.GetChildren().Any())
        {
            CertificateRequirement = CertificateConfigUtility.ConvertCertificateRequirement(sectionCertificateRequirement);
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
            && (CertificateConfigUtility.EqualCertificateConfigQ(SigningCertificateConfig, other.SigningCertificateConfig))
            && (CertificateConfigUtility.EqualCertificateConfigsQ(SigningCertificateConfigs, other.SigningCertificateConfigs))
            && (CertificateConfigUtility.EqualCertificateCollectionQ(SigningCertificateCollection, other.SigningCertificateCollection))
            && (string.Equals(Algorithm, other.Algorithm))
            && (CertificateRequirement.Equals(other.CertificateRequirement))
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
        result.Add(SigningCertificateConfig);
        foreach (var item in SigningCertificateConfigs) { result.Add(item); }
        result.Add(SigningCertificateCollection);
        result.Add(Algorithm, StringComparer.Ordinal);
        return result.ToHashCode();
    }
}
