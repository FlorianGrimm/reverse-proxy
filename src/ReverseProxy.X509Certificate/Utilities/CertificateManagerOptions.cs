using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Options of <see cref="CertificateManager"/>
/// </summary>
public class CertificateManagerOptions
{
    /// <summary>
    /// The timespan a certificate is considered valid.
    /// </summary>
    public TimeSpan CacheTimeSpan { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Rootfolder for Certificate.
    /// </summary>
    public string CertificateRoot { get; set; } = string.Empty;

    /// <summary>
    /// Allow self signed certificate.
    /// </summary>
    public bool AllowSelfSigned { get; set; } = false;

    /// <summary>
    /// The configuration for certificates by an id.
    /// </summary>
    public Dictionary<string, ListCertificateConfiguration> Certificates { get; set; } = new (StringComparer.Ordinal);

    public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

    public X509VerificationFlags VerificationFlags { get; set; } = X509VerificationFlags.NoFlag;

    public Action<X509Certificate2, X509ChainPolicy>? ConfigureX509ChainPolicy { get; set; }
}
