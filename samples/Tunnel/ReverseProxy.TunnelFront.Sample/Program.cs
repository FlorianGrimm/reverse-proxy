using System.Net.Http.Headers;
using System.Numerics;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms;
using Yarp.Sample;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ;

builder.WebHost.UseReverseProxyTunnelFrontEnd()
    //.LoadFromConfig(builder.Configuration.GetSection("ReverseProxy:TunnelFronts"))
    ;

var app = builder.Build();

app.MapReverseProxy();

app.Run();
