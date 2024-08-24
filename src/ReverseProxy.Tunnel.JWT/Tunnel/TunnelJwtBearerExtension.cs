using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelJwtBearerExtension {
    public static IReverseProxyBuilder AddTunnelServicesJwtBearer(this IReverseProxyBuilder builder, IConfiguration configuration)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationJwtBearer>());
        builder.Services.AddOptions<TunnelAuthenticationJwtBearerOptions>().Configure(options => options.Bind(configuration));

        return builder;
    }
}
