using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Defines the options used to configure the authentication transport.
/// </summary>
public class AuthorizationTransportOptions
{
    public string? Scheme { get; set; }

    /// <summary>
    /// Prevents the Authorization header from being modified if it already contains a Bearer token.
    /// </summary>
    public bool DoNotModifyAuthorizationIfBaerer { get; set; }

    public HashSet<string> ExcludeClaimType { get; set; } = new HashSet<string>();
    public Dictionary<string, string> TransformClaimType { get; set; } = new Dictionary<string, string>();
    public HashSet<string> IncludeClaimType { get; set; } = new HashSet<string>();

    public string? Issuer { get; set; }
    public string? Audience { get; set; }
    public string? AuthenticationType { get; set; }
    public TimeSpan NotBefore { get; set; } = TimeSpan.FromSeconds(-30);
    public TimeSpan Expires { get; set; } = TimeSpan.FromSeconds(+30);

    public CertificateConfig? SigningCertificateConfig { get; set; }
    public Func<SigningCredentials>? CreateSigningKey { get; set; }
    public string Algorithm { get; set; } = SecurityAlgorithms.RsaSha256;
}

