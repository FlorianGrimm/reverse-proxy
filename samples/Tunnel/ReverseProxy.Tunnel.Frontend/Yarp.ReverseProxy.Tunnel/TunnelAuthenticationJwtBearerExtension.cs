using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

internal static class TunnelAuthenticationJwtBearerExtension {
    public static IReverseProxyBuilder AddTunnelAuthenticationJwtBearer(this IReverseProxyBuilder builder, IConfiguration configuration)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationJwtBearer>());
        builder.Services.AddOptions<TunnelAuthenticationJwtBearerOptions>().Bind(configuration);

        return builder;
    }
}
