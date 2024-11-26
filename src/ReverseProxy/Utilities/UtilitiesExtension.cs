using System.Collections.Generic;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

public static class UtilitiesExtension
{
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    public static IServiceCollection TryAddNoOpCertificateManager(this IServiceCollection services)
    {
        services.TryAdd(ServiceDescriptor.Transient<ICertificateManager, NoOpCertificateManager>());
        services.TryAdd(ServiceDescriptor.Transient<ICertificatePasswordDecryptor, NoOpCertificatePasswordDecryptor>());

        return services;
    }
}
