using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;
internal sealed class TunnelAuthenticationJwtBearer
    : ITunnelAuthenticationService
{
    public string GetAuthenticationName() => "JwtBearer";

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {

        var oid = context.User.FindFirst("oid")?.Value;
        var sub = context.User.FindFirst("sub")?.Value;
        var isAppOnly = oid != null && sub != null && oid == sub;
#warning TODO: here
        return true;
    }

    public static void ConfigureBearerToken(JwtBearerOptions options)
    {
        options.Events ??= new JwtBearerEvents();
        options.Events.OnMessageReceived = async context =>
        {
            System.Console.Out.WriteLine($"---------- MessageReceived {context.Token}");
            await Task.CompletedTask;
        };
        options.Events.OnTokenValidated = async context =>
        {
            //context.
            //var claims = new List<Claim>
            //{
            //    new Claim("oid", context.Principal.FindFirst("oid")?.Value ?? ""),
            //    new Claim("sub", context.Principal.FindFirst("sub")?.Value ?? ""),
            //};
            //var appIdentity = new ClaimsIdentity(claims, "app");
            //context.Principal.AddIdentity(appIdentity);
            var securityToken = context.SecurityToken;
            System.Console.Out.WriteLine($"---------- Id:{securityToken.Id} Issuer:{securityToken.Issuer}");
            if (context.Principal is ClaimsPrincipal claimsPrincipal)
            {
                System.Console.Out.WriteLine("-------------- ClaimsPrincipal");
            }
            else
            {
                System.Console.Out.WriteLine("-------------- NOT ClaimsPrincipal");
            }
            
            await Task.CompletedTask;
        };
        //((BearerTokenEvents)options.Events).OnTokenValidated = context =>
        //    {
        //        var claims = new List<Claim>
        //        {
        //            new Claim("oid", context.Principal.FindFirst("oid")?.Value ?? ""),
        //            new Claim("sub", context.Principal.FindFirst("sub")?.Value ?? ""),
        //        };
        //        var appIdentity = new ClaimsIdentity(claims, "app");
        //        context.Principal.AddIdentity(appIdentity);
        //        return Task.CompletedTask;
        //    };
    }
}
