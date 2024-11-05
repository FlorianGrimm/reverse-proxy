using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class CertificateManagerServiceCollectionExtensions
{
    public static IServiceCollection AddReverseProxyCertificateManager(
        this IServiceCollection services,
        Action<CertificateManagerOptions>? configure = default,
        string? sectionName = default
        )
    {
        services.TryAddSingleton<ICertificateManager, CertificateManagerPeriodicalRefresh>();
        services.TryAddSingleton<ICertificateStoreLoader, CertificateStoreLoader>();
        services.TryAddSingleton<ICertificateFileLoader, CertificateFileLoader>();
        services.TryAddSingleton<CertificateManagerFileWatcher>();
        var optionsBuilder = services.AddOptions<CertificateManagerOptions>();
        if (configure is not null)
        {
            _ = optionsBuilder.Configure(configure);
        }
        if (sectionName is not null)
        {
            _ = optionsBuilder.Configure<IConfiguration>((options, configuration) =>
            {
                options.Bind(configuration.GetSection(sectionName));
            });
        }
        _ = optionsBuilder.PostConfigure<IHostEnvironment>(static (options, hostEnvironment) => options.PostConfigure(hostEnvironment));
        return services;
    }

    public static IServiceCollection ConfigureReverseProxyCertificateManager(
       this IServiceCollection services,
       Action<CertificateManagerOptions>? configure = default,
       string? sectionName = default
       )
    {
        var optionsBuilder = services.AddOptions<CertificateManagerOptions>();
        if (configure is not null)
        {
            _ = optionsBuilder.Configure(configure);
        }
        if (sectionName is not null)
        {
            _ = optionsBuilder.Configure<IConfiguration>((options, configuration) =>
            {
                options.Bind(configuration.GetSection(sectionName));
            });
        }
        return services;
    }
}
