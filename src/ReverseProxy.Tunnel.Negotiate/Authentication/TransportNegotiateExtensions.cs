using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using System;

using Yarp.ReverseProxy.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

public  static class TransportNegotiateExtensions
{
    public static AuthenticationBuilder AddTransportNegotiateAuthentication(
    this AuthenticationBuilder builder,
    string? authenticationScheme = default,
    IConfiguration? configuration = default,
    Action<TransportNegotiateOptions>? configure = default)
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }
        if (string.IsNullOrEmpty(authenticationScheme))
        {
            authenticationScheme = TransportNegotiateDefaults.AuthenticationScheme;
        }
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
}
