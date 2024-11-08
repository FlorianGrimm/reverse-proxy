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
        services.TryAddSingleton<ICertificateManagerFileWatcher, CertificateManagerFileWatcher>();
        services.TryAddSingleton<ICertificatePasswordProvider, CertificatePasswordProvider>();
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
       IConfiguration? configuration = default,
       Action<CertificateManagerOptions>? configure = default
       )
    {
        var optionsBuilder = services.AddOptions<CertificateManagerOptions>();
        if (configure is not null || configuration is not null)
        {
            _ = optionsBuilder.Configure(options =>
            {
                if (configuration is not null)
                {
                    options.Bind(configuration);
                }
                if (configure is not null)
                {
                    configure(options);
                }
            });
        }

        return services;
    }

    public static IServiceCollection AddReverseProxyRSACertificatePasswordProvider(
           this IServiceCollection services,
           Action<RSACertificatePasswordOptions>? configure = default
           )
    {
        services.TryAddSingleton<ICertificatePasswordProvider, RSACertificatePasswordProvider>();
        var optionsBuilder = services.AddOptions<RSACertificatePasswordOptions>();
        if (configure is not null)
        {
            _ = optionsBuilder.Configure(options =>
            {
                if (configure is not null)
                {
                    configure(options);
                }
            });
        }
        return services;
    }
}
