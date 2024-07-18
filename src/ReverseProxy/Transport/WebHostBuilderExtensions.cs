// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Linq;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Utilities;

namespace Microsoft.AspNetCore.Builder;

public static class WebHostBuilderExtensions
{
    /// <summary>
    /// Enable the tunnel transport on the backend.
    /// Foreach tunnel-config connections are opend to URL/_tunnel/RemoteTunnelId or URL/_tunnel/TunnelId
    /// </summary>
    /// <param name="builder">this</param>
    /// <param name="configureTunnelHttp2">configure transport tunnel for Http2.</param>
    /// <param name="configureTunnelWebSocket">configure transport tunnel for WebSocket.</param>
    /// <returns></returns>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .AddTunnelTransport();
    /// </example>
    public static IReverseProxyBuilder AddTunnelTransport(
        this IReverseProxyBuilder builder,
        Action<TransportTunnelHttp2Options>? configureTunnelHttp2 = default,
        Action<TransportTunnelWebSocketOptions>? configureTunnelWebSocket = default
        )
    {
        var services = builder.Services
            .AddSingleton<ITunnelChangeListener, TransportTunnelConnectionChangeListener>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelHttp2ConnectionListenerFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelWebSocketConnectionListenerFactory>());

        services.AddSingleton<TransportTunnelHttp2Authentication>()
            .TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authentication, TransportTunnelHttp2AuthenticationAnonymous>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authentication, TransportTunnelHttp2AuthenticationCertificate>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authentication, TransportTunnelHttp2AuthenticationWindows>());

        services.AddSingleton<TransportTunnelWebSocketAuthentication>()
            .TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthentication, TransportTunnelWebSocketAuthenticationAnonymous>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthentication, TransportTunnelWebSocketAuthenticationCertificate>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthentication, TransportTunnelWebSocketAuthenticationWindows>());

        services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();
        services.TryAddSingleton<CertificatePathWatcher>();

        if (configureTunnelHttp2 is not null)
        {
            _ = services.Configure(configureTunnelHttp2);
        }

        if (configureTunnelWebSocket is not null)
        {
            _ = services.Configure(configureTunnelWebSocket);
        }

        _ = services.Configure<KestrelServerOptions>(ConfigureTransportTunnels);

        return builder;
    }

    private static void ConfigureTransportTunnels(KestrelServerOptions options)
    {
        var proxyConfigManager = options.ApplicationServices.GetRequiredService<ProxyConfigManager>();
        var listAuthenticationNameH2 = options.ApplicationServices.GetRequiredService<TransportTunnelHttp2Authentication>().GetAuthenticationNames();
        var listAuthenticationNameWS = options.ApplicationServices.GetRequiredService<TransportTunnelWebSocketAuthentication>().GetAuthenticationNames();
        var tunnels = proxyConfigManager.GetTransportTunnels();
        foreach (var tunnel in tunnels)
        {
            var cfg = tunnel.Model.Config;
            var remoteTunnelId = cfg.GetRemoteTunnelId();
            var host = cfg.Url.TrimEnd('/');

            var transport = cfg.Transport;

            var cfgAuthenticationMode = cfg.Authentication.Mode;

            if (transport == TransportMode.TunnelHTTP2)
            {
                if (listAuthenticationNameH2.FirstOrDefault(n => string.Equals(n, cfgAuthenticationMode)) is { } authenticationMode)
                {
                    var uriTunnel = new Uri($"{host}/_Tunnel/H2/{authenticationMode}/{remoteTunnelId}");
                    options.Listen(new UriEndPointHttp2(uriTunnel, tunnel.TunnelId));
                    continue;
                }
                else
                {
                    throw new NotSupportedException($"Authentication {cfgAuthenticationMode} is unknown");
                }
            }
            if (transport == TransportMode.TunnelWebSocket)
            {
                if (listAuthenticationNameH2.FirstOrDefault(n => string.Equals(n, cfgAuthenticationMode)) is { } authenticationMode)
                {
                    var uriTunnel = new Uri($"{host}/_Tunnel/WS/{authenticationMode}/{remoteTunnelId}");
                    options.Listen(new UriWebSocketEndPoint(uriTunnel, tunnel.TunnelId));
                    continue;
                }
                else
                {
                    throw new NotSupportedException($"Authentication {cfgAuthenticationMode} is unknown");
                }
            }
        }
    }

    public static IReverseProxyBuilder ConfigureCertificateConfigOptions(
        this IReverseProxyBuilder builder,
        Action<CertificateConfigOptions>? configure = default,
        IConfiguration? configuration = default
        )
    {
        {
            var optionsBuilder = builder.Services.AddOptions<CertificateConfigOptions>();
            if (configuration is { })
            {
                _ = optionsBuilder.Configure((options) =>
                {
                    options.Bind(configuration.GetSection(CertificateConfigOptions.SectionName));
                });
            }

            if (configure is { })
            {
                _ = optionsBuilder.Configure(configure);
            }
        }

        return builder;
    }
}
