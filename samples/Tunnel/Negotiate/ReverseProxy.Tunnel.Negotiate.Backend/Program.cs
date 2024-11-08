using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Transport;

namespace ReverseProxy.Tunnel.Backend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        //builder.Services.AddSingleton<IPostConfigureOptions<JwtBearerOptions>, ConfigureTokenValidationParameters>();
        builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
            .AddNegotiate()
            .AddJwtBearer(options =>
            {
                options.Authority = "itsme";
                options.Audience = "itsyou";
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters.ValidateIssuer = true;
                options.TokenValidationParameters.ValidateAudience = true;
                options.TokenValidationParameters.ValidIssuer = "itsme";
                options.TokenValidationParameters.ValidAudience = "itsyou";
                //options.TokenValidationParameters.IssuerSigningKeyResolver = TokenValidationIssuerSigningKeyResolver.CreateIssuerSigningKeyResolver(
                //    builder.Services
                //    );
                ///(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)
                //(token, securityToken, kid, parameters) => new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("itsme"));
            });

        builder.Services.AddAuthorization(options =>
        {
            options.FallbackPolicy = options.DefaultPolicy;
        });


        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);
        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTunnelTransport()
            .AddTunnelTransportNegotiate()
            .AddReverseProxyCertificateManager(
                configure: (options) => {
                    options.CertificateRootPath = System.AppContext.BaseDirectory;
                })
            .AddAuthorizationTransportTransformProvider(
                configure: (options) =>
                {
                    //options.AuthorizationPolicyName = "RequireValidUser";
                    options.Issuer = "itsme";
                    options.Audience = "itsyou";
                    options.SigningCertificateConfig = new CertificateConfig()
                    {
                        Path = "myJwt2024.pfx",
                        Password = "testPassword2024",
                        AllowInvalid = true
                    };
                })
            ;

        var app = builder.Build();

        // app.UseHttpsRedirection() will redirect if the request is a tunnel request;
        // which means that the browser is redirected to https://{tunnelId}/... which is not what we want.
        _ = app.UseWhen(
            static context => !context.TryGetTransportTunnelByUrl(out _),
            app => app.UseHttpsRedirection()
        );

        app.UseAuthorization();

        app.MapReverseProxy();

        app.Run();
    }


}
