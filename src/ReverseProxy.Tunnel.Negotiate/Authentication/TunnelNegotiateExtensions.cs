using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;

using System;

using Yarp.ReverseProxy.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelNegotiateExtensions
{
    public static AuthenticationBuilder AddTunnelServicesNegotiate(
        this AuthenticationBuilder builder,
        string? authenticationScheme = default,
        IConfiguration? configuration = default,
        Action<Yarp.ReverseProxy.Authentication.TunnelNegotiateOptions>? configure = default)
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }
        if (string.IsNullOrEmpty(authenticationScheme))
        {
            authenticationScheme = TunnelNegotiateDefaults.AuthenticationScheme;
        }
        var optionsBuilder = builder.Services.AddOptions<Yarp.ReverseProxy.Authentication.TunnelNegotiateOptions>();
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

        builder.AddScheme<Yarp.ReverseProxy.Authentication.TunnelNegotiateOptions, TunnelNegotiateHandler>(authenticationScheme, configure);

        return builder;
    }
}
