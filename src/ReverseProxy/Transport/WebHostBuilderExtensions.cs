// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

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
    /// </summary>
    /// <param name="builder">this</param>
    /// <param name="configureTunnelHttp2">configure transport tunnel for Http2.</param>
    /// <param name="configureTunnelWebSocket">configure transport tunnel for WebSocket.</param>
    /// <returns></returns>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .UseTunnelTransport();
    /// </example>
    public static IReverseProxyBuilder AddTunnelTransport(
        this IReverseProxyBuilder builder,
        Action<TransportTunnelHttp2Options>? configureTunnelHttp2 = default,
        Action<TransportTunnelWebSocketOptions>? configureTunnelWebSocket = default
        )
    {
        var services = builder.Services
            .AddSingleton<ITunnelChangeListener, TransportTunnelConnectionChangeListener>();
        services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();
        services.TryAddSingleton<CertificatePathWatcher>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelHttp2ConnectionListenerFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConnectionListenerFactory, TransportTunnelWebSocketConnectionListenerFactory>());

        services.AddSingleton<TransportTunnelHttp2Authentication>()
            .TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelHttp2Authentication, TransportTunnelHttp2AuthenticationCertificate>());

        services.AddSingleton<TransportTunnelWebSocketAuthentication>()
            .TryAddEnumerable(ServiceDescriptor.Singleton<ITransportTunnelWebSocketAuthentication, TransportTunnelWebSocketAuthenticationCertificate>());

        if (configureTunnelHttp2 is not null)
        {
            _ = builder.Services.Configure(configureTunnelHttp2);
        }

        if (configureTunnelWebSocket is not null)
        {
            _ = builder.Services.Configure(configureTunnelWebSocket);
        }

        _ = builder.Services.Configure<KestrelServerOptions>(ConfigureTransportTunnels);

        return builder;
    }

    private static void ConfigureTransportTunnels(KestrelServerOptions options)
    {
        var proxyConfigManager = options.ApplicationServices.GetRequiredService<ProxyConfigManager>();
        var tunnels = proxyConfigManager.GetTransportTunnels();
        foreach (var tunnel in tunnels)
        {
            var cfg = tunnel.Model.Config;
            var remoteTunnelId = cfg.GetRemoteTunnelId();
            var host = cfg.Url.TrimEnd('/');

            var uriTunnel = new Uri($"{host}/_Tunnel/{remoteTunnelId}");
            var transport = cfg.Transport;
            if (transport == TransportMode.TunnelHTTP2)
            {
                options.Listen(new UriEndPointHttp2(uriTunnel, tunnel.TunnelId));
                continue;
            }
            if (transport == TransportMode.TunnelWebSocket)
            {
                options.Listen(new UriWebSocketEndPoint(uriTunnel, tunnel.TunnelId));
                continue;
            }
        }
    }

    public static IReverseProxyBuilder AddTunnelTransportAuthenticationCertificate(
        this IReverseProxyBuilder builder,
        Action<CertificateConfigOptions>? configureCertificateConfigOptions = default,
        IConfiguration? configuration = default
        )
    {
        if (configuration is null
            && builder is ReverseProxyBuilder reverseProxyBuilder)
        {
            configuration = reverseProxyBuilder.GetConfiguration();
        }

        {
            var optionsBuilder = builder.Services.AddOptions<CertificateConfigOptions>();
            if (configuration is { })
            {
                optionsBuilder.Configure((options) =>
                {
                    options.Bind(configuration.GetSection(CertificateConfigOptions.SectionName));
                });
            }

            if (configureCertificateConfigOptions is { })
            {
                optionsBuilder.Configure(configureCertificateConfigOptions);
            }
        }

        return builder;
    }
}
