using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class CertificateManagerServiceCollectionExtensions
{
    public static IServiceCollection AddReverseProxyCertificateManager(
        this IServiceCollection services,
        string? sectionName = null
        )
    {
        services.TryAddSingleton<ICertificateManager, CertificateManagerPeriodicalRefresh>();
        services.TryAddSingleton<ICertificateStoreLoader, CertificateStoreLoader>();
        services.TryAddSingleton<ICertificateFileLoader, CertificateFileLoader>();
        services.TryAddSingleton<CertificateManagerFileWatcher>();
        services.AddOptions<CertificateManagerOptions>()
            .Configure<IConfiguration>((options, configuration) => {
                if (sectionName is not null)
                {
                    options.Bind(configuration.GetSection(sectionName));
                }
            })
            .PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));
        return services;
    }
}
