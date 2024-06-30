// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;


public static class TunnelExensions
{
    public static IServiceCollection AddTunnelServices(this IServiceCollection services)
    {
        services.TryAddSingleton<TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, TunnelConnectionChannelManager.ClusterChangeListener>());

        services.TryAddSingleton<TunnelHTTP2Route>();
        services.TryAddSingleton<TunnelWebSocketRoute>();

        services.TryAddSingleton<TransportHttpClientFactorySelector>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelHTTP2HttpClientFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelWebSocketHttpClientFactory>());

        services.TryAddSingleton<TunnelAuthenticationConfigService>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationConfigService, TunnelAuthenticationAnonymous>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationConfigService, TunnelAuthenticationCertificate>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationConfigService, TunnelAuthenticationWindows>());

        services.TryAddSingleton<CertificatePathWatcher>();
        services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();
        return services;
    }

    /// <summary>
    /// Enables tunnels (listener - on the front end) configured
    /// in the <see cref="Yarp.ReverseProxy.Configuration.ClusterConfig"/> Transport (e.g. TunnelHTTP2)
    /// </summary>
    /// <param name="builder">this builder</param>
    /// <returns>fluent this</returns>
    /// <example>
    ///    builder.Services.AddReverseProxy()
    ///        .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    ///        .AddTunnelServices();
    /// </example>
    public static IReverseProxyBuilder AddTunnelServices(
    this IReverseProxyBuilder builder)
    {
        _ = builder.Services.AddTunnelServices();
        return builder;
    }

    internal static void MapTunnels(
        this IEndpointRouteBuilder endpoints,
        Action<IEndpointConventionBuilder>? configureTunnelHTTP2 = default,
        Action<IEndpointConventionBuilder>? configureTunnelWebSocket = default)
    {

        if (endpoints.ServiceProvider.GetService<TunnelHTTP2Route>() is { } tunnelHTTP2Route)
        {
            _ = tunnelHTTP2Route.Map(endpoints, configureTunnelHTTP2);
        }

        if (endpoints.ServiceProvider.GetService<TunnelWebSocketRoute>() is { } tunnelWebSocketRoute)
        {
            _ = tunnelWebSocketRoute.Map(endpoints, configureTunnelWebSocket);
        }
    }

    public static IReverseProxyBuilder AddTunnelServicesAuthenticationCertificate(
        this IReverseProxyBuilder builder,
        Action<CertificateAuthenticationOptions>? configureCertificateAuthenticationOptions = default,
        Action<TunnelAuthenticationCertificateOptions>? configureTunnelAuthenticationCertificateOptions = default,
        Action<CertificateConfigOptions>? configureCertificateConfigOptions = default,
        Action<KestrelServerOptions>? configureKestrelServerOptions = default,
        IConfiguration? configuration = default
        )
    {
        if (configuration is null
            && builder is ReverseProxyBuilder reverseProxyBuilder)
        {
            configuration = reverseProxyBuilder.GetConfiguration();
        }

        {
            var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationCertificateOptions>();
            if (configuration is { })
            {
                optionsBuilder.Configure((options) =>
                {
                    options.Bind(configuration.GetSection(TunnelAuthenticationCertificateOptions.SectionName));
                });
            }
            if (configureTunnelAuthenticationCertificateOptions is { })
            {
                optionsBuilder.Configure(configureTunnelAuthenticationCertificateOptions);
            }
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

        _ = builder.Services.Configure<KestrelServerOptions>(kestrelServerOptions =>
        {
            var tunnelAuthenticationConfigService = kestrelServerOptions.ApplicationServices.GetRequiredService<TunnelAuthenticationConfigService>();
            tunnelAuthenticationConfigService.ConfigureKestrelServer(kestrelServerOptions);

            if (configureKestrelServerOptions is { })
            {
                configureKestrelServerOptions(kestrelServerOptions);
            }
        });

        var authenticationBuilder = builder.Services.AddAuthentication();
        _ = authenticationBuilder.AddCertificate(
            authenticationScheme: CertificateAuthenticationDefaults.AuthenticationScheme,
            configureOptions: certificateAuthenticationOptions =>
            {
                certificateAuthenticationOptions.Events ??= new CertificateAuthenticationEvents();
                certificateAuthenticationOptions.Events.OnCertificateValidated = (context) =>
                {
                    if (context.ClientCertificate is not null)
                    {
                        context.Success();
                    }
                    else
                    {
                        context.NoResult();
                    }
                    return Task.CompletedTask;
                };
                if (configureCertificateAuthenticationOptions is { } configure)
                {
                    configure(certificateAuthenticationOptions);
                }
            });

        return builder;
    }

    /*
    public static IReverseProxyBuilder AddTunnelServicesAuthenticationWindows(
        this IReverseProxyBuilder builder,
        Action<NegotiateOptions>? configureNegotiateOptions = default,
        Action<KestrelServerOptions>? configureKestrelServerOptions = default,
        IConfiguration? configuration = default
        )
    {
        if (configuration is null
            && builder is ReverseProxyBuilder reverseProxyBuilder)
        {
            configuration = reverseProxyBuilder.GetConfiguration();
        }

        _ = builder.Services.Configure<KestrelServerOptions>(kestrelServerOptions =>
            {
                var tunnelAuthenticationConfigService = kestrelServerOptions.ApplicationServices.GetRequiredService<TunnelAuthenticationConfigService>();
                tunnelAuthenticationConfigService.ConfigureKestrelServer(kestrelServerOptions);

                if (configureKestrelServerOptions is { })
                {
                    configureKestrelServerOptions(kestrelServerOptions);
                }
            });

        var authenticationBuilder = builder.Services.AddAuthentication();
        _ = authenticationBuilder.AddNegotiate(
            authenticationScheme: NegotiateDefaults.AuthenticationScheme,
            configureOptions: negotiateOptions =>
            {
                if (configureNegotiateOptions is { })
                {
                    configureNegotiateOptions(negotiateOptions);
                }
            });

        return builder;
    }
    */
}
