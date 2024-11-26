// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods to configure the bearer token authentication.
/// </summary>
public static class TransportJwtBearerTokenExtensions
{
    /// <summary>
    /// Adds bearer token authentication.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configuration">configuration to bind the options.</param>
    /// <param name="configure">Action used to configure the bearer token authentication options.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddTransportJwtBearerToken(
        this AuthenticationBuilder builder,
        string? authenticationScheme = default,
        IConfiguration? configuration = default,
        Action<TransportJwtBearerTokenOptions>? configure = default)
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }
        if (string.IsNullOrEmpty(authenticationScheme))
        {
            authenticationScheme = TransportJwtBearerTokenDefaults.AuthenticationScheme;
        }

        //if (authenticationScheme is null) { throw new ArgumentNullException(nameof(authenticationScheme)); }
        //if (configure is null) { throw new ArgumentNullException(nameof(configure)); }
        //builder.AddBearerToken(
        //    authenticationScheme,
        //    configure: (BearerTokenOptions options) => {
        //        if (options.Events is null) {
        //            options.Events = new BearerTokenEvents();
        //        }
        //        options.Events.OnMessageReceived
        //        if (configure is { }) {
        //            configure(options);
        //        }
        //    });
        builder.Services.TryAddNoOpCertificateManager();

#if NET8_0_OR_GREATER
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JsonOptions>, TransportJwtBearerTokenConfigureJsonOptions>());
#endif
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<TransportJwtBearerTokenOptions>, TransportJwtBearerTokenConfigureOptions>());
        var optionsBuilder = builder.Services.AddOptions<TransportJwtBearerTokenOptions>();
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

        builder.AddScheme<TransportJwtBearerTokenOptions, TransportJwtBearerTokenHandler>(authenticationScheme, configure);

        return builder;
    }

    private const string Prefix = "Bearer ";
    public static string? GetBearerToken(StringValues authorization)
    {
        foreach (var valueAuthorization in authorization)
        {
            if (valueAuthorization is { Length: > 7 }
                && valueAuthorization.StartsWith(Prefix))
            {
                return valueAuthorization.Substring(Prefix.Length);
            }
        }
        return null;
    }
    public static void Bind(this TransportJwtBearerTokenOptions that, IConfiguration configuration)
    {

        if (configuration[nameof(TransportJwtBearerTokenOptions.Audience)] is { Length: > 0 } valueAudience)
        {
            that.Audience = valueAudience;
        }

        var sectionValidIssuers = configuration.GetSection(nameof(TransportJwtBearerTokenOptions.ValidIssuers));
        List<string>? listValidIssuers = default;
        foreach (var section in sectionValidIssuers.GetChildren())
        {
            if (section.Value is { Length: > 0 } value)
            {
                (listValidIssuers ??= new()).Add(value);
            }
        }
        if (listValidIssuers is { })
        {
            that.ValidIssuers = listValidIssuers;
        }

        if (configuration[nameof(TransportJwtBearerTokenOptions.SigningKeySecret)] is { Length: > 0 } valueSigningKeySecret)
        {
            that.SigningKeySecret = valueSigningKeySecret;
        }

        if (configuration[nameof(TransportJwtBearerTokenOptions.SigningCertificate)] is { Length: > 0 } valueSigningCertificate)
        {
            that.SigningCertificate = valueSigningCertificate;
        }
    }
}
