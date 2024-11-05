// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;
using Yarp.ReverseProxy.Tunnel;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelExtensions
{


    /// <summary>
    /// Adds the services required for tunneling.
    /// </summary>
    /// <param name="builder">this</param>
    /// <param name="configure">Optional configuration delegate</param>
    /// <param name="configuration">Optional configuration</param>
    /// <returns>fluent this</returns>
    public static IReverseProxyBuilder AddTunnelServicesCertificate(
        this IReverseProxyBuilder builder,
        Action<TunnelAuthenticationCertificateOptions>? configure = default,
        IConfiguration? configuration = default
        )
    {
        var services = builder.Services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationCertificateWebSocket>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelAuthenticationService, TunnelAuthenticationCertificateHttp2>());

        var optionsBuilder = services.AddOptions<TunnelAuthenticationCertificateOptions>();
        if (configuration is { })
        {
            optionsBuilder.Configure((options) =>
            {
                options.Bind(configuration.GetSection(TunnelAuthenticationCertificateOptions.SectionName));
            });
        }
        if (configure is { })
        {
            optionsBuilder.Configure(configure);
        }

        // CertificateLoader
        services.AddReverseProxyCertificateManager();

        // ClientCertificateValidationUtility
        services.AddSingleton<ClientCertificateValidationUtility>();
        services.AddOptions<ClientCertificateValidationOptions>()
            .PostConfigure<IOptions<TunnelAuthenticationCertificateOptions>>(
                (ClientCertificateValidationOptions options, IOptions<TunnelAuthenticationCertificateOptions> tunnelAuthenticationCertificateOptions) =>
                {
                    var source = tunnelAuthenticationCertificateOptions.Value;
                    options.IgnoreSslPolicyErrors = source.IgnoreSslPolicyErrors;
                    options.CustomValidation = source.CustomValidation;
                });

        return builder;
    }

    public static IReverseProxyBuilder ConfigureTunnelAuthenticationCertificateOptions(
        this IReverseProxyBuilder builder,
        Action<TunnelAuthenticationCertificateOptions>? configure = default,
        IConfiguration? configuration = default
        )
    {
        var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationCertificateOptions>();
        if (configuration is { })
        {
            optionsBuilder.Configure((options) =>
            {
                options.Bind(configuration.GetSection(TunnelAuthenticationCertificateOptions.SectionName));
            });
        }
        if (configure is { })
        {
            optionsBuilder.Configure(configure);
        }

        return builder;
    }
}
