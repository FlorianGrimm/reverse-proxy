using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

using System;

using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

public static class TunnelCertificateExtensions {
    public static AuthenticationBuilder AddTunnelServicesCertificate(
         this AuthenticationBuilder builder,
         string? authenticationScheme = default,
         IConfiguration? configuration = default,
         Action<Yarp.ReverseProxy.Authentication.TunnelCertificateOptions>? configure = default
         )
    {
        if (builder is null) { throw new ArgumentNullException(nameof(builder)); }

        if (string.IsNullOrEmpty(authenticationScheme))
        {
            authenticationScheme = TunnelCertificateDefaults.AuthenticationScheme;
        }
        var optionsBuilder = builder.Services.AddOptions<Yarp.ReverseProxy.Authentication.TunnelCertificateOptions>();
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

        builder.AddScheme<Yarp.ReverseProxy.Authentication.TunnelCertificateOptions, TunnelCertificateHandler>(authenticationScheme, configure);

        return builder;
    }
}
