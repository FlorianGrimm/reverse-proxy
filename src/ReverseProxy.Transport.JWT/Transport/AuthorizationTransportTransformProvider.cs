using System.Collections.Concurrent;

using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public class AuthenticationTransportTransformProvider : ITransformProvider
{
    private readonly AuthorizationTransportOptions _options;
    private readonly AuthenticationTransportSigningCertificate _signingCertificate;

    public AuthenticationTransportTransformProvider(
        IYarpCertificateLoader certificateLoader,
        YarpCertificatePathWatcher? certificatePathWatcher,
        IOptions<AuthorizationTransportOptions> options
        )
    {
        _options = options.Value;
        _signingCertificate = new AuthenticationTransportSigningCertificate(
            certificateLoader,
            certificatePathWatcher,
            _options);
    }

    public void ValidateCluster(TransformClusterValidationContext context) {
        if (context.Cluster is { } cluster && cluster.IsTunnelTransport())
        {
            if (_options.SigningCertificateConfig is { } config)
            {
                if (_signingCertificate.GetCertificate() is null)
                {
                    context.Errors.Add(new System.ArgumentException("SigningCertificate", "No signing certificate found."));
                }
            }
        }
    }

    public void ValidateRoute(TransformRouteValidationContext context) { }

    public void Apply(TransformBuilderContext context)
    {
        var requestTransform = new AuthenticationTransportRequestTransform(_options, _signingCertificate);
        context.RequestTransforms.Add(requestTransform);
    }
}
