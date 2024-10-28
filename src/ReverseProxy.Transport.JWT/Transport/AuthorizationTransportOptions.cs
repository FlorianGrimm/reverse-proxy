using System;
using System.Collections.Generic;

using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Gets or sets the adjustment to the 'Not Before' time for the JWT token.
/// This adjustment is applied to account for clock skew between systems.
/// Options for configuring authorization transport.
/// </summary>
public class AuthorizationTransportOptions
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
    public bool DoNotModifyAuthorizationIfBaerer { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether authenticate headers should be removed.
    /// If false nothing is done.
    /// If true and DoNotModifyAuthorizationIfBaerer is true and a Bearer token is found, the WWW-Authenticate header is removed.
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
    /// Gets or sets the function to create the signing key.
    /// </summary>
    public Func<SigningCredentials>? CreateSigningKey { get; set; }

    /// <summary>
    /// Gets or sets the algorithm used for signing the token. Default is RsaSha256
    /// </summary>
    public string Algorithm { get; set; } = SecurityAlgorithms.RsaSha256;

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
}
