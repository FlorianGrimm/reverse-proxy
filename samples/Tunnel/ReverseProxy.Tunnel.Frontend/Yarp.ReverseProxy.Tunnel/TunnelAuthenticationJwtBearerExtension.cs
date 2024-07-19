using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.Extensions.DependencyInjection;

internal static class TunnelAuthenticationJwtBearerExtension {
    public static IReverseProxyBuilder AddTunnelAuthenticationJwtBearer(this IReverseProxyBuilder builder)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationJwtBearer>());
        builder.Services.AddOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions>().BindConfiguration("AzureAd");

        return builder;
    }
}
