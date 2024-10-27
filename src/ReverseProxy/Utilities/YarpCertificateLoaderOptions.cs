// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public sealed class YarpCertificateLoaderOptions
{
    public string? CertificateRoot { get; set; }

    public Func<CertificateConfig, string?>? CertificatePassword { get; set; }

    public void Bind(IConfiguration configuration)
    {
        CertificateRoot = configuration[nameof(CertificateRoot)];
    }

    internal string? GetCertificatePassword(CertificateConfig certificateConfig)
    {
        if (CertificatePassword is null)
        {
            return certificateConfig.Password;
        }
        else
        {
            return CertificatePassword(certificateConfig);
        }
    }

    public void PostConfigure(IHostEnvironment hostEnvironment)
    {
        if (string.IsNullOrEmpty(CertificateRoot))
        {
            CertificateRoot = hostEnvironment.ContentRootPath;
        }
    }
}
