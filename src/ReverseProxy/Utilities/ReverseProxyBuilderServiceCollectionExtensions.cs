using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.AspNetCore.Builder;

public static class ReverseProxyBuilderServiceCollectionExtensions
{
    public static IReverseProxyBuilder AddReverseProxyCertificateManager(
        this IReverseProxyBuilder reverseProxyBuilder,
        Action<CertificateManagerOptions>? configure = default,
        string? sectionName = default
    )
    {
        reverseProxyBuilder.Services.AddReverseProxyCertificateManager(configure, sectionName);
        return reverseProxyBuilder;
    }

    public static IReverseProxyBuilder ConfigureReverseProxyCertificateManager(
        this IReverseProxyBuilder reverseProxyBuilder,
       IConfiguration? configuration = default,
       Action<CertificateManagerOptions>? configure = default
    )
    {
        reverseProxyBuilder.Services.ConfigureReverseProxyCertificateManager(configuration, configure);
        return reverseProxyBuilder;
    }
}
