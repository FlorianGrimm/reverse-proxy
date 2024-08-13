using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Transport;

namespace Microsoft.AspNetCore.Builder;

public static class TransportTunnelAuthenticationJwtBearerExtension {
    public static IReverseProxyBuilder AddTunnelTransportAuthenticationJwtBearer(
        this IReverseProxyBuilder builder
        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authentication, TransportTunnelHttp2AuthenticationJwtBearer>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthentication, TransportTunnelWebSocketAuthenticationJwtBearer>());
        services.AddOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions>().BindConfiguration("AzureAd");

        return builder;
    }
}
