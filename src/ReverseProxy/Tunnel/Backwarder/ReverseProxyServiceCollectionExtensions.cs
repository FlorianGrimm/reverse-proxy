#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Tunnel.Backwarder;

namespace Microsoft.Extensions.DependencyInjection;

public static partial class ReverseProxyServiceCollectionExtensions
{
    public static IServiceCollection AddTunnelServices(this IServiceCollection services)
    {
        var tunnelFactory = new TunnelClientFactory();
        services.AddSingleton(tunnelFactory);
        services.AddSingleton<IForwarderHttpClientFactory>(tunnelFactory);
        return services;
    }
}
