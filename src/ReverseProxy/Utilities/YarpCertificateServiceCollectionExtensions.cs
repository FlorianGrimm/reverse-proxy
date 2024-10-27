using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class YarpCertificateServiceCollectionExtensions
{
    public static IServiceCollection AddReverseProxyCertificateLoader(this IServiceCollection services)
    {
        services.AddReverseProxyCertificateLoader();

        services.TryAddSingleton<ICertificateCollectionFactory, CertificateCollectionFactory>();
        services.TryAddSingleton<YarpCertificatePathWatcher>();
        services.TryAddSingleton<IYarpCertificateLoader, YarpCertificateLoader>();
        services.AddOptions<YarpCertificateLoaderOptions>()
            .PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));

        return services;
    }
}
