using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Tunnel;

namespace Microsoft.AspNetCore.Builder;
public static partial class ReverseProxyIEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapReverseProxyTunnelFrontendToBackend(this IEndpointRouteBuilder endpoints) {
        var proxyConfigManager = endpoints.ServiceProvider.GetRequiredService<ProxyConfigManager>();
        proxyConfigManager.InitialLoadAsync().GetAwaiter().GetResult();

        // TODO: check transport
        var enableHTTP2 = proxyConfigManager.GetTunnelFrontendToBackends().Any();
        if (enableHTTP2) {

            var pattern = "/Tunnel/HTTP2/{TunnelId}";

            endpoints.MapPost(pattern, async (HttpContext context) => await TunnelHandler.HandleHttp2Tunnel(context));
        }
        return endpoints;
    }
}
