// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Transport;
using Yarp.ReverseProxy.Utilities;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions for <see cref="IServiceCollection"/>
/// used to register the ReverseProxy's components.
/// </summary>
public static class ReverseProxyServiceCollectionExtensions
{

    public static IReverseProxyBuilder AddAuthorizationTransportTransformProvider(
        this IReverseProxyBuilder builder,
        IConfiguration? configuration = default,
        Action<AuthorizationTransportOptions>? configure = default)
    {
        var services = builder.Services;
        services.TryAddNoOpCertificateManager();
        services.TryAddSingleton<AuthorizationTransportJWTUtilityService>();

        var optionsBuilder = services.AddOptions<AuthorizationTransportOptions>();
        if (configuration is not null || configure is not null)
        {
            optionsBuilder.Configure((options) => {
                if (configuration is not null)
                {
                    options.Bind(configuration);
                }
                if (configure is not null) {
                    configure(options);
                }
            });
        }

        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransformProvider, AuthorizationTransportTransformProvider>());
        // services.TryAddEnumerable(ServiceDescriptor.Singleton<ITransformProvider, AuthorizationTransportTransformProvider>());
        return builder;
    }

    public static void Bind(
        this AuthorizationTransportOptions that,
        IConfiguration configuration)
    {
        if (bool.TryParse(configuration[nameof(AuthorizationTransportOptions.EnableForAllCluster)], out var valueEnableForAllCluster))
        {
            that.EnableForAllCluster = valueEnableForAllCluster;
        }
        if (bool.TryParse(configuration[nameof(AuthorizationTransportOptions.DoNotModifyAuthorizationIfBearer)], out var valueDoNotModifyAuthorizationIfBearer))
        {
            that.DoNotModifyAuthorizationIfBearer = valueDoNotModifyAuthorizationIfBearer;
        }
        if (bool.TryParse(configuration[nameof(AuthorizationTransportOptions.RemoveHeaderAuthenticate)], out var valueRemoveHeaderAuthenticate))
        {
            that.RemoveHeaderAuthenticate = valueRemoveHeaderAuthenticate;
        }
        if (configuration[nameof(AuthorizationTransportOptions.Scheme)] is { Length: > 0 } valueScheme)
        {
            that.Scheme = valueScheme;
        }
        foreach (var valueExcludeClaimType in configuration.GetSection(nameof(AuthorizationTransportOptions.ExcludeClaimType)).GetChildren())
        {
            if (valueExcludeClaimType.Value is { Length: > 0 } value)
            {
                that.ExcludeClaimType.Add(value);
            }
        }
        foreach (var valueTransformClaimType in configuration.GetSection(nameof(AuthorizationTransportOptions.TransformClaimType)).GetChildren())
        {
            if (valueTransformClaimType.Key is { Length: > 0 } key
                && valueTransformClaimType.Value is { Length: > 0 } value)
            {
                that.TransformClaimType.Add(key, value);
            }
        }
        foreach (var valueIncludeClaimType in configuration.GetSection(nameof(AuthorizationTransportOptions.IncludeClaimType)).GetChildren())
        {
            if (valueIncludeClaimType.Value is { Length: > 0 } value)
            {
                that.IncludeClaimType.Add(value);
            }
        }
        if (configuration[nameof(AuthorizationTransportOptions.Issuer)] is { Length: > 0 } valueIssuer)
        {
            that.Issuer = valueIssuer;
        }
        if (configuration[nameof(AuthorizationTransportOptions.Audience)] is { Length: > 0 } valueAudience)
        {
            that.Audience = valueAudience;
        }
        if (configuration[nameof(AuthorizationTransportOptions.AuthenticationType)] is { Length: > 0 } valueAuthenticationType)
        {
            that.AuthenticationType = valueAuthenticationType;
        }
        if (TimeSpan.TryParse(configuration[nameof(AuthorizationTransportOptions.AdjustNotBefore)], out var valueAdjustNotBefore))
        {
            that.AdjustNotBefore = valueAdjustNotBefore;
        }
        if (TimeSpan.TryParse(configuration[nameof(AuthorizationTransportOptions.AdjustExpires)], out var valueAdjustExpires))
        {
            that.AdjustExpires = valueAdjustExpires;
        }

        if (configuration[nameof(AuthorizationTransportOptions.SigningKeySecret)] is { Length: > 0 } valueSigningKeySecret)
        {
            that.SigningKeySecret = valueSigningKeySecret;
        }

        if (configuration[nameof(AuthorizationTransportOptions.SigningCertificate)] is { Length: > 0 } valueSigningCertificate)
        {
            that.SigningCertificate = valueSigningCertificate;
        }

        if (configuration[nameof(AuthorizationTransportOptions.Algorithm)] is { Length: > 0 } valueAlgorithm)
        {
            // SecurityAlgorithms.RsaSha256 = "RS256";
            that.Algorithm = valueAlgorithm;
        }
    }
}
