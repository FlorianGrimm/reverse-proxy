using Yarp.ReverseProxy.Tunnel;

namespace Yarp.TunnelApplication;

public class Program
{
    public static int Main(string[] args)
    {

        var builder = WebApplication.CreateBuilder(args);
        if (args.Length > 0)
        {
            var configFile = args[0];
            var fileInfo = new FileInfo(configFile);
            if (fileInfo.Exists)
            {
                builder.Configuration.AddJsonFile(fileInfo.FullName, optional: false, reloadOnChange: true);
            }
            else
            {
                Console.Error.WriteLine($"Could not find '{configFile}'.");
                return 2;
            }
        }

        builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
        builder.Logging.AddLocalFile(
            configure: (options) =>
            {
                if (System.Environment.GetEnvironmentVariable("HOME") is { Length: > 0 } home)
                {
                    options.BaseDirectory = home;
                }
                else
                {
                    options.BaseDirectory = builder.Environment.ContentRootPath;
                }
                options.LogDirectory = "LogFiles\\Application";

            },
            configuration: builder.Configuration.GetSection("Logging:LocalFile"));

        // Add services to the container.

        var reverseProxyBuilder = builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

        // TransportTunnel (Backend)
        {
            var listTransportTunnelTransportAuthentication = builder.Configuration.GetSection("ReverseProxy:Tunnels")
                    .GetChildren()
                    .Select(sectionTunnel => sectionTunnel.GetSection("TransportAuthentication:Mode").Value)
                    .Where(value => value is { Length: > 0 })
                    .ToList();

            var enableTransportTunnel = builder.Configuration.GetSection("ReverseProxy:Tunnels").GetChildren().Any();
            if (enableTransportTunnel)
            {
                reverseProxyBuilder.AddTransportTunnel();
                if (builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic") is { } configurationAuthenticationBasic
                    && configurationAuthenticationBasic.Exists()
                    && listTransportTunnelTransportAuthentication.Contains(TunnelBasicConstants.AuthenticationMode))
                {
                    reverseProxyBuilder.AddTransportTunnelBasic();
                }
                if (listTransportTunnelTransportAuthentication.Contains(TunnelJwtBearerConstants.AuthenticationMode)
                    && builder.Configuration.GetSection("AzureAD") is { } configurationAzureAD
                    && configurationAzureAD.Exists())
                {
                    reverseProxyBuilder.AddTransportTunnelJwtBearer();
                }
                if (listTransportTunnelTransportAuthentication.Contains(TunnelCertificateConstants.AuthenticationMode)
                    && builder.Configuration.GetSection("CertificateManager") is { } configurationCertificateManager
                    && configurationCertificateManager.Exists()
                    && builder.Configuration.GetSection("ReverseProxy:AuthorizationTransport") is { } configurationAuthorizationTransport
                    && configurationAuthorizationTransport.Exists())
                {
                    builder.Services.AddCertificateManager(
                        configuration: configurationCertificateManager);
                    reverseProxyBuilder.AddTransportTunnelCertificate(
                        configuration: configurationAuthorizationTransport);
                }
            }
        }

        // TunnelServices (Frontend)
        {
            // TunnelServices needs a TransportAuthentication
            // no TransportAuthentication -> no TunnelServices => weak but hopefully ok
            var listTunnelServicesTransportAuthentication = builder.Configuration.GetSection("ReverseProxy:Clusters")
                    .GetChildren()
                    .Select(sectionCluster => sectionCluster.GetSection("TransportAuthentication").Value)
                    .Where(value => value is { Length: > 0 })
                    .ToList();

            var enableTunnelServices = listTunnelServicesTransportAuthentication.Any();
            if (enableTunnelServices)
            {
                reverseProxyBuilder.AddTunnelServices();
                if (builder.Configuration.GetSection("ReverseProxy:AuthenticationBasic") is { } configurationAuthenticationBasic
                    && configurationAuthenticationBasic.Exists()
                    && listTunnelServicesTransportAuthentication.Contains(TunnelBasicConstants.AuthenticationMode))
                {
                    reverseProxyBuilder.AddTunnelServicesBasic();
                }
                if (listTunnelServicesTransportAuthentication.Contains(TunnelJwtBearerConstants.AuthenticationMode)
                    && builder.Configuration.GetSection("AzureAD") is { } configurationAzureAD
                    && configurationAzureAD.Exists())
                {
                    reverseProxyBuilder.AddTunnelServicesJwtBearer(
                        configuration: configurationAzureAD);
                }
                if (listTunnelServicesTransportAuthentication.Contains(TunnelCertificateConstants.AuthenticationMode)
                    && builder.Configuration.GetSection("CertificateManager") is { } configurationCertificateManager
                    && configurationCertificateManager.Exists()
                    && builder.Configuration.GetSection("ReverseProxy:AuthorizationTransport") is { } configurationAuthorizationTransport
                    && configurationAuthorizationTransport.Exists())
                {
                    builder.Services.AddCertificateManager(
                        configuration: configurationCertificateManager);
                    reverseProxyBuilder.AddTunnelServicesCertificate(
                        configuration: configurationAuthorizationTransport);
                }
            }
        }

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        app.UseHttpsRedirection();
        app.MapReverseProxy();

        app.Run();
        return 0;
    }
}
