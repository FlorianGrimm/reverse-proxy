using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class CertificateServiceCollectionExtensions
{
    public static IServiceCollection AddReverseProxyCertificateLoader(this IServiceCollection services)
    {
        services.AddReverseProxyCertificateLoader();
        services.TryAddSingleton<CertificatePathWatcher>();
        services.TryAddSingleton<ICertificateLoader, CertificateLoader>();
        services.AddOptions<CertificateLoaderOptions>()
            .PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));

        return services;
    }
}
