// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Authentication;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;

public sealed class TunnelAuthenticationCertificateOptions
{
    /// <summary>
    /// Ignore the SSL policy errors.
    /// </summary>
    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; }

    /// <summary>
    /// Specifies the callback method to validate the certificate;
    /// </summary>
    public Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? CustomValidation { get; set; }

    //
    // Summary:
    //     Specifies whether the certificate revocation list is checked during authentication.
    public bool? CheckCertificateRevocation { get; set; }

    //
    // Summary:
    //     Specifies allowable SSL protocols. Defaults to System.Security.Authentication.SslProtocols.None
    //     which allows the operating system to choose the best protocol to use, and to
    //     block protocols that are not secure. Unless your app has a specific reason not
    //     to, you should use this default.

    public SslProtocols? SslProtocols { get; set; }

    public Action<HttpsConnectionAdapterOptions>? ConfigureHttpsConnectionAdapterOptions { get; set; }

#warning TODO Cleanup

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
}

public static class TunnelAuthenticationCertificateOptionsExtensions
{
    /// <summary>
    /// Binds the configuration to the options.
    /// </summary>
    /// <param name="that">this</param>
    /// <param name="configuration">the source configuration</param>
    public static void Bind(
        this TunnelAuthenticationCertificateOptions that,
        IConfiguration configuration
        )
    {
        if (System.Enum.TryParse<SslPolicyErrors>(configuration[nameof(TunnelAuthenticationCertificateOptions.IgnoreSslPolicyErrors)], out var valueIgnoreSslPolicyErrors))
        {
            that.IgnoreSslPolicyErrors = valueIgnoreSslPolicyErrors;
        }

        if (System.Enum.TryParse<CertificateTypes>(configuration[nameof(TunnelAuthenticationCertificateOptions.AllowedCertificateTypes)], out var allowedCertificateTypes))
        {
            that.AllowedCertificateTypes = allowedCertificateTypes;
        }
    }
}
