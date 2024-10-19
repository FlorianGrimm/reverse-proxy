using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Transforms.Builder;

namespace Yarp.ReverseProxy.Transport;

public class AuthenticationTransformProvider : ITransformProvider

{
    private readonly AuthenticationTransformOptions _options;

    public AuthenticationTransformProvider(
        IOptions<AuthenticationTransformOptions> options
        )
    {
        _options = options.Value;
    }

    public void ValidateCluster(TransformClusterValidationContext context)
    {
    }

    public void ValidateRoute(TransformRouteValidationContext context)
    {
    }

    public void Apply(TransformBuilderContext context)
    {
        context.RequestTransforms.Add(new AuthenticationRequestTransform(_options));
    }
}

