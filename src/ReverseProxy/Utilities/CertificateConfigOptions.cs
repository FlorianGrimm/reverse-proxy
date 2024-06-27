// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;

public sealed class CertificateConfigOptions
{
    public const string SectionName = "CertificateConfig";

    public string? CertificateRoot { get; set; }

    public void Bind(IConfiguration configuration)
    {
        CertificateRoot = configuration[nameof(CertificateRoot)];
    }

    public static string GetCertificateRoot(
        IOptions<CertificateConfigOptions> options,
        IHostEnvironment hostEnvironment)
    {
        var result = hostEnvironment.ContentRootPath;

        var optionsValue = options.Value;
        if (optionsValue.CertificateRoot is { Length: > 0 } certificateRoot)
        {
            if (string.Equals(certificateRoot, "Assembly", StringComparison.OrdinalIgnoreCase))
            {
                result = System.AppContext.BaseDirectory;
            }
            else if (certificateRoot.IndexOf("%Assembly%") >= 0)
            {
                result = certificateRoot.Replace("%Assembly%", System.AppContext.BaseDirectory);
            }
            else if (string.Equals(certificateRoot, "ContentRootPath", StringComparison.OrdinalIgnoreCase))
            {
                result = hostEnvironment.ContentRootPath;
            }
            else if (certificateRoot.IndexOf("%ContentRootPath%") >= 0)
            {
                result = certificateRoot.Replace("%ContentRootPath%", hostEnvironment.ContentRootPath);
            }
        }

        return result;
    }
}
