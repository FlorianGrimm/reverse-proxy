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
        if (configuration is { } || configure is { })
        {
            optionsBuilder.Configure((options) =>
            {
                if (configuration is { })
                {
                    options.Bind(configuration);
                }
                if (configure is { })
                {
                    configure(options);
                }
            });
        }

        // CertificateLoader
        services.TryAddNoOpCertificateManager();

        // TODO: ClientCertificateValidationUtility
        // TODO: services.AddSingleton<ClientCertificateValidationHttp2>();
        // TODO: services.AddOptions<ClientCertificateValidationHttp2Options>()
        // TODO:     .PostConfigure<IOptions<TunnelAuthenticationCertificateOptions>>(
        // TODO:         (ClientCertificateValidationHttp2Options options, IOptions<TunnelAuthenticationCertificateOptions> tunnelAuthenticationCertificateOptions) =>
        // TODO:         {
        // TODO:             var source = tunnelAuthenticationCertificateOptions.Value;
        // TODO:             options.IgnoreSslPolicyErrors = source.IgnoreSslPolicyErrors;
        // TODO:             options.CustomValidation = source.CustomValidation;
        // TODO:         });

        return builder;
    }

    public static IReverseProxyBuilder ConfigureTunnelAuthenticationCertificateOptions(
        this IReverseProxyBuilder builder,
        Action<TunnelAuthenticationCertificateOptions>? configure = default,
        IConfiguration? configuration = default
        )
    {
        var optionsBuilder = builder.Services.AddOptions<TunnelAuthenticationCertificateOptions>();
        if (configuration is { } || configure is { })
        {
            optionsBuilder.Configure((options) =>
            {
                if (configuration is { })
                {
                    options.Bind(configuration);
                }
                if (configure is { })
                {
                    configure(options);
                }
            });
        }

        return builder;
    }
}
