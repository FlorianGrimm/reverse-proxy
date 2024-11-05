using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// This class is used to configure the behaviour of the CertificateManager.
/// </summary>
public class CertificateManagerOptions
{
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan CoolDownTime { get; set; } = TimeSpan.FromMinutes(10);

    public string? CertificateRootPath { get; set; }

    public CertificateRequirement CertificateRequirement { get; set; } = new();

    public Action<X509ChainPolicy>? ConfigureChainPolicy { get; set; }

    public void Bind(IConfiguration configuration)
    {
        if (configuration[nameof(RefreshInterval)] is { Length: > 0 } textRefreshInterval
            && TimeSpan.TryParse(textRefreshInterval, out var refreshInterval)) {
            RefreshInterval = refreshInterval;
        }

        if (configuration[nameof(CoolDownTime)] is { Length: > 0 } textCoolDownTime
            && TimeSpan.TryParse(textCoolDownTime, out var coolDownTime))
        {
            CoolDownTime = coolDownTime;
        }

        CertificateRootPath = configuration[nameof(CertificateRootPath)];
    }

    public void PostConfigure(IHostEnvironment hostEnvironment)
    {
        if (string.IsNullOrEmpty(CertificateRootPath))
        {
            CertificateRootPath = hostEnvironment.ContentRootPath;
        }
    }
}
