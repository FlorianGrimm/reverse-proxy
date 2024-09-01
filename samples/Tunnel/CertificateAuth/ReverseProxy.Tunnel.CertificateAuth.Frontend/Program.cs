#if README

--------------------------------
| Browser                      |
| https://localhost:5001/index |
--------------------------------
            |           ^
            |           |
            v           |
--------------------------------
| ReverseProxy.Tunnel.Frontend |
| https://localhost:5001/      |
--------------------------------
        |     ||     /\
        |     ||     ||
        ^     \/     ||
--------------------------------
| ReverseProxy.Tunnel.Backend  |
| https://localhost:5003/      |
--------------------------------
                 |  ^
                 |  |
                 v  |
--------------------------------
| ReverseProxy.Tunnel.API      |
| https://localhost:5005/      |
--------------------------------

#endif

using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Yarp.ReverseProxy.Tunnel;

namespace ReverseProxy.Tunnel.Frontend;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddUserSecrets("ReverseProxy");
        builder.Logging.AddLocalFileLogger(builder.Configuration, builder.Environment);

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetRequiredSection("ReverseProxy"))
            .AddTunnelServices()
            .AddTunnelServicesCertificate((options) =>
                 {
                     options.IgnoreSslPolicyErrors = SslPolicyErrors.RemoteCertificateChainErrors;
                     options.AllowedCertificateTypes = CertificateTypes.All;
                     options.RevocationMode = X509RevocationMode.NoCheck;
                     options.ValidateCertificateUse = false;
                     options.ValidateValidityPeriod = false;
                 },
                 default
                 )
            .ConfigureCertificateLoaderOptions((options) =>
                {
                    options.CertificateRoot = System.AppContext.BaseDirectory;
                }
            );

            var authenticationBuilder = builder.Services.AddAuthentication();
            authenticationBuilder
               .AddCertificate(options =>
               {
                   // this sample uses the SelfSigned certificates.
                   options.AllowedCertificateTypes = CertificateTypes.All;
                   options.RevocationMode = X509RevocationMode.NoCheck;
                   options.ValidateCertificateUse = false;
                   options.ValidateValidityPeriod = false;

                   options.Events = new CertificateAuthenticationEvents
                   {
                       OnCertificateValidated = context =>
                       {
                           if (context.ClientCertificate != null)
                           {
                               context.Success();
                           }
                           else
                           {
                               context.NoResult();
                           }
                           return Task.CompletedTask;
                       }
                   };

               });

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.MapReverseProxy();

        app.Run();
    }
}
