using System;

using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public class AuthorizationTransportTransformProvider : ITransformProvider
{
    private readonly AuthorizationTransportSigningCertificate _signingCertificate;
    private AuthorizationTransportOptions _options;

    public AuthorizationTransportTransformProvider(
        ICertificateManager certificateManager,
        IOptionsMonitor<AuthorizationTransportOptions> options
    )
    {
        _signingCertificate = new AuthorizationTransportSigningCertificate(
            certificateManager,
            options);
        options.OnChange(OptionsOnChange);
        _options = options.CurrentValue;
    }

    private void OptionsOnChange(AuthorizationTransportOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }

        _options = options;
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
        if (_options.IsEnabled(context.Cluster))
        {
            using (var sharedSigningCredentials = _signingCertificate.GetSigningCredentials())
            {
                if (sharedSigningCredentials?.Value is null)
                {
                    context.Errors.Add(
                        new InvalidOperationException("No signing certificate found."));
                }
            }
        }
    }

    public void ValidateRoute(TransformRouteValidationContext context) { }

    public void Apply(TransformBuilderContext context)
    {
        var requestTransform = new AuthorizationTransportRequestTransform(_options, _signingCertificate);
        context.RequestTransforms.Add(requestTransform);
    }
}
