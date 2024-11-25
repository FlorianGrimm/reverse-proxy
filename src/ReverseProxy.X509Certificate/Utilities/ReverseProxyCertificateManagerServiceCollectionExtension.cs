using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class ReverseProxyCertificateManagerServiceCollectionExtension
{
    public static IServiceCollection AddCertificateManager(
        this IServiceCollection services,
        IConfiguration? configuration = default,
        Action<CertificateManagerOptions>? configure = default)
    {
        services.TryAddSingleton<ICertificatePasswordDecryptor, NoOpCertificatePasswordDecryptor>();
        services.TryAddTransient<ICertificateManager, CertificateManager>();
        services.TryAddEnumerable(ServiceDescriptor.Transient<ICertificateLoader, CertificateLoaderFile>());
        services.TryAddEnumerable(ServiceDescriptor.Transient<ICertificateLoader, CertificateLoaderStore>());

        var optionsBuilder = services.AddOptions<CertificateManagerOptions>();
        if (configuration is { } || configure is { })
        {
            optionsBuilder.Configure((options) =>
            {
                if (configuration is { })
                {
                    options.Bind(configuration);
                }
                if (configure is { })
                {
                    configure(options);
                }
            });
        }
        return services;
    }
    public static IServiceCollection AddCertificateManager(
        this IServiceCollection services,
        ICertificateManager instance)
    {
        services.Add(ServiceDescriptor.Singleton<ICertificateManager>(instance));
        return services;
    }
}
