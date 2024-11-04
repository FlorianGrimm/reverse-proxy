using System;

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class YarpCertificateServiceCollectionExtensions
{
    [Obsolete]
    public static IServiceCollection AddReverseProxyCertificateLoader(this IServiceCollection services)
    {
        services.TryAddSingleton<IYarpCertificatePathWatcher, YarpCertificatePathWatcher>();
        services.TryAddSingleton<IYarpCertificateLoader, YarpCertificateLoader>();
        services.TryAddSingleton<IYarpCertificateCollectionFactory, YarpCertificateCollectionFactory>();
        services.AddOptions<YarpCertificateLoaderOptions>()
            .PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));

        return services;
    }
}