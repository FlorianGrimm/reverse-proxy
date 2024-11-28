using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for adding certificate management services to the dependency injection container.
/// </summary>
public static class ReverseProxyCertificateManagerExtensions
{
    /// <summary>
    /// Adds certificate management services to the service collection.
    /// </summary>
    /// <param name="reverseProxyBuilder">The reverse proxy builder.</param>
    /// <param name="configuration">Optional configuration for the certificate manager.</param>
    /// <param name="configure">Optional action to configure the certificate manager options.</param>
    /// <returns>Fluent this.</returns>
    public static IReverseProxyBuilder AddCertificateManager(
        this IReverseProxyBuilder reverseProxyBuilder,
        IConfiguration? configuration = default,
        Action<CertificateManagerOptions>? configure = default)
    {
        reverseProxyBuilder.Services.AddCertificateManager(configuration, configure);
        return reverseProxyBuilder;
    }

    /// <summary>
    /// Adds certificate management services to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">Optional configuration for the certificate manager.</param>
    /// <param name="configure">Optional action to configure the certificate manager options.</param>
    /// <returns>Fluent this.</returns>
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

    /// <summary>
    /// Adds a specific certificate manager instance to the service collection.
    /// </summary>
    /// <param name="reverseProxyBuilder">The reverse proxy builder.</param>
    /// <param name="instance">The certificate manager instance.</param>
    /// <returns>Fluent this.</returns>
    public static IReverseProxyBuilder AddCertificateManager(
        this IReverseProxyBuilder reverseProxyBuilder,
        ICertificateManager instance)
    {
        reverseProxyBuilder.Services.AddCertificateManager(instance);
        return reverseProxyBuilder;
    }

    /// <summary>
    /// Adds a specific certificate manager instance to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="instance">The certificate manager instance.</param>
    /// <returns>Fluent this.</returns>
    public static IServiceCollection AddCertificateManager(
        this IServiceCollection services,
        ICertificateManager instance)
    {
        services.Add(ServiceDescriptor.Singleton<ICertificateManager>(instance));
        return services;
    }
}
