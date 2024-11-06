using System;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelJwtBearerExtension
{
    public static IReverseProxyBuilder AddTunnelServicesJwtBearer(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = null,
        Action<TunnelAuthenticationJwtBearerOptions>? configure = null)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationJwtBearerWebSocket>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationJwtBearerHttp2>());

        var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationJwtBearerOptions>();
        if ((configuration is { }) || (configure is not null))
        {
            optionsBuilder.Configure(options =>
            {
                if (configuration is { })
                {
                    options.Bind(configuration);
                }
                if (configure is not null)
                {
                    configure(options);
                }
            });
        }
        return builder;
    }
}
