// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Claims;
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
        services.TryAddSingleton<TunnelAuthenticationConfigService>();
        services.TryAddSingleton<ITunnelAuthenticationConfigService, TunnelAuthenticationCertificate>();
        services.TryAddSingleton<TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, TunnelConnectionChannelManager.ClusterChangeListener>());
        services.TryAddSingleton<TransportHttpClientFactorySelector>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelHTTP2HttpClientFactory>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransportHttpClientFactorySelector, TunnelWebSocketHttpClientFactory>());
        services.TryAddSingleton<TunnelHTTP2Route>();
        services.TryAddSingleton<TunnelWebSocketRoute>();
        services.TryAddSingleton<CertificatePathWatcher>();
        services.TryAddSingleton<ICertificateConfigLoader, CertificateConfigLoader>();
        return services;
    }

    public static IServiceCollection AddTunnelServicesCertificate(this IServiceCollection services)
    {
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
            });

        var authenticationBuilder = builder.Services.AddAuthentication();
        _ = authenticationBuilder.AddCertificate(options =>
            {
                options.Events = new CertificateAuthenticationEvents
                {
                    OnCertificateValidated = context =>
                    {
                        //context.HttpContext.RequestServices

                        if (context.ClientCertificate is not null)
                        {
                            // TODO: is this really usefull
                            var claims = new[]
                            {
                                new Claim(
                                    ClaimTypes.NameIdentifier,
                                    context.ClientCertificate.Subject,
                                    ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer),
                                new Claim(
                                    ClaimTypes.Name,
                                    context.ClientCertificate.Subject,
                                    ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer)
                            };
                            context.Principal = new ClaimsPrincipal(
                                new ClaimsIdentity(claims, context.Scheme.Name));

                            context.Success();
                        }
                        return Task.CompletedTask;
                    }
                };
                if (configureCertificateAuthenticationOptions is { } configure)
                {
                    configure(options);
                }
            });

        builder.Services.AddAuthorization(
            options =>
            {
                options.AddPolicy("RequireCertificate", policy =>
                {
                    policy.AuthenticationSchemes.Add(CertificateAuthenticationDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                });
            });

        // TODO: this does not enforce that the cluster's cert must match the current cert
        // adding policy RequireCertificateFor<ClusterId> would prevent dynamic cluster config that uses tunnel
        // so testing on the Map - Delegate??

        return builder;
    }
}
