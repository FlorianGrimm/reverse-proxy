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
        IYarpCertificateCollectionFactory yarpCertificateCollectionFactory,
        IOptions<AuthorizationTransportOptions> options
    )
    {
        _options = options.Value;
        _signingCertificate = new AuthorizationTransportSigningCertificate(
            yarpCertificateCollectionFactory,
            _options);
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
        if (_options.IsEnabled(context.Cluster))
        {
            if (_signingCertificate.GetCertificate() is null)
            {
                context.Errors.Add(new System.ArgumentException("No signing certificate found.","SigningCertificate"));
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
