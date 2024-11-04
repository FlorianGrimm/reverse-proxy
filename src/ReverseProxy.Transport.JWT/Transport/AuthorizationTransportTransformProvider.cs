using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public class AuthorizationTransportTransformProvider : ITransformProvider
{
    private readonly AuthorizationTransportOptions _options;
    private readonly AuthorizationTransportSigningCertificate _signingCertificate;

    public AuthorizationTransportTransformProvider(
        ICertificateManager certificateManager,
        IOptions<AuthorizationTransportOptions> options
    )
    {
        _options = options.Value;
        _signingCertificate = new AuthorizationTransportSigningCertificate(
            certificateManager,
            _options);
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
        if (_options.IsEnabled(context.Cluster))
        {
            using var certificate = _signingCertificate.GetCertificate();
            if (certificate?.Value is null)
            {
                context.Errors.Add(
                    new InvalidOperationException("No signing certificate found."));
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
