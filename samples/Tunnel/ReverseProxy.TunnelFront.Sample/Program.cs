using System.Net.Http.Headers;
using System.Numerics;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ;

builder.Services.AddReverseProxyTunnel()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ;
var app = builder.Build();

app.MapReverseProxyTunnelFrontendToBackend();
app.MapReverseProxy();

app.Run();
