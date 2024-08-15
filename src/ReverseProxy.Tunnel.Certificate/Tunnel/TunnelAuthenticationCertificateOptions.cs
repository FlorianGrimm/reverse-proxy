// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.Certificate;

namespace Yarp.ReverseProxy.Tunnel;

public sealed class TunnelAuthenticationCertificateOptions
{
    public const string SectionName = "TunnelAuthenticationCertificate";

    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; }

    /// <summary>
    /// Using Microsoft.AspNetCore.Authentication.Certificate
    /// </summary>
    public bool SourceAuthenticationProvider { get; set; }

    /// <summary>
    /// Using the client certificate from http request directly.
    /// </summary>
    public bool SourceRequest { get; set; }

    /// <summary>
    /// Value indicating the types of certificates accepted - used if SourceRequest is trúe.
    /// </summary>
    /// <value>
    /// Defaults to <see cref="CertificateTypes.Chained"/>.
    /// </value>
    public CertificateTypes AllowedCertificateTypes { get; set; } = CertificateTypes.Chained;

    /// <summary>
    /// Collection of X509 certificates which are trusted components of the certificate chain - used if SourceRequest is trúe.
    /// </summary>
    public X509Certificate2Collection CustomTrustStore { get; set; } = new();

    /// <summary>
    /// Collection of X509 certificates which are added to the X509Chain.ChainPolicy.ExtraStore of the certificate chain - used if SourceRequest is trúe.
    /// </summary>
    public X509Certificate2Collection AdditionalChainCertificates { get; set; } = new X509Certificate2Collection();

    /// <summary>
    /// Method used to validate certificate chains against <see cref="CustomTrustStore"/> - used if SourceRequest is trúe.
    /// </summary>
    /// <value>
    /// Defaults to <see cref="X509ChainTrustMode.System"/>.
    /// </value>
    /// <remarks>This property must be set to <see cref="X509ChainTrustMode.CustomRootTrust"/> to enable <see cref="CustomTrustStore"/> to be used in certificate chain validation.</remarks>
    public X509ChainTrustMode ChainTrustValidationMode { get; set; } = X509ChainTrustMode.System;

    /// <summary>
    /// Flag indicating whether the client certificate must be suitable for client
    /// authentication, either via the Client Authentication EKU, or having no EKUs
    /// at all. If the certificate chains to a root CA all certificates in the chain must be validated
    /// for the client authentication EKU - used if SourceRequest is trúe.
    /// </summary>
    /// <value>
    /// Defaults to <see langword="true" />.
    /// </value>
    public bool ValidateCertificateUse { get; set; } = true;

    /// <summary>
    /// Flag indicating whether the client certificate validity period should be checked - used if SourceRequest is trúe.
    /// </summary>
    /// <value>
    /// Defaults to <see langword="true" />.
    /// </value>
    public bool ValidateValidityPeriod { get; set; } = true;

    /// <summary>
    /// Specifies which X509 certificates in the chain should be checked for revocation - used if SourceRequest is trúe.
    /// </summary>
    /// <value>
    /// Defaults to <see cref="X509RevocationFlag.ExcludeRoot" />.
    /// </value>
    public X509RevocationFlag RevocationFlag { get; set; } = X509RevocationFlag.ExcludeRoot;

    /// <summary>
    /// Specifies conditions under which verification of certificates in the X509 chain should be conducted - used if SourceRequest is trúe.
    /// </summary>
    /// <value>
    /// Defaults to <see cref="X509RevocationMode.Online" />.
    /// </value>
    public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

    /// <summary>
    ///
    /// </summary>
    public Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? IsCertificateValid { get; set; }

    public void Bind(IConfiguration configuration)
    {
        if (System.Enum.TryParse<SslPolicyErrors>(configuration[nameof(IgnoreSslPolicyErrors)], out var valueIgnoreSslPolicyErrors))
        {
            IgnoreSslPolicyErrors = valueIgnoreSslPolicyErrors;
        }
        
        if (bool.TryParse(configuration[nameof(SourceAuthenticationProvider)], out var sourceAuth))
        {
            SourceAuthenticationProvider = sourceAuth;
        }


        if (bool.TryParse(configuration[nameof(SourceRequest)], out var sourceRequest))
        {
            SourceRequest = sourceRequest;
        }

        if (System.Enum.TryParse<CertificateTypes>(configuration[nameof(AllowedCertificateTypes)], out var allowedCertificateTypes))
        {
            AllowedCertificateTypes = allowedCertificateTypes;
        }
    }
}
