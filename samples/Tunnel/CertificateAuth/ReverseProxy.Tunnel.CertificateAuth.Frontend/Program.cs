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

        var useAuthenticationProvider = args.Any(a => a == "AuthenticationProvider");

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetRequiredSection("ReverseProxy"))
            .AddTunnelServices()
            .AddTunnelServicesCertificate((options) =>
                 {
                     options.SourceAuthenticationProvider = useAuthenticationProvider;
                     options.SourceRequest = !useAuthenticationProvider;
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

        if (useAuthenticationProvider)
        {
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
        }

        // this sample uses the SelfSigned certificates so disable the some check.
        /*
        builder.WebHost.ConfigureKestrel(kestrelServerOptions =>
        {
            kestrelServerOptions.ConfigureEndpointDefaults(listenOptions =>
            {
                listenOptions.UseHttps(ConfigHttpsConnectionAdapterOptions);
            });
            kestrelServerOptions.ConfigureHttpsDefaults(ConfigHttpsConnectionAdapterOptions);
        });
        static void ConfigHttpsConnectionAdapterOptions(HttpsConnectionAdapterOptions httpsConnectionAdapterOptions)
        {
            httpsConnectionAdapterOptions.CheckCertificateRevocation = false;
            httpsConnectionAdapterOptions.ClientCertificateMode = Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.AllowCertificate;
            httpsConnectionAdapterOptions.ClientCertificateValidation = (certificate, chain, sslPolicyErrors) =>
            {
                return sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors;
            };
        }
        */

        var app = builder.Build();

        app.UseHttpsRedirection();

        if (useAuthenticationProvider)
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        app.MapReverseProxy();

        app.Run();
    }
}
