// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;

using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Transforms.Builder;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;


/// <summary>
/// Provides transforms for authorization transport.
/// </summary>
public sealed class AuthorizationTransportTransformProvider : ITransformProvider {
    private readonly AuthorizationTransportSigningCertificate _signingCertificate;
    private AuthorizationTransportOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationTransportTransformProvider"/> class.
    /// </summary>
    /// <param name="certificateManager">The certificate manager.</param>
    /// <param name="options">The options monitor for <see cref="AuthorizationTransportOptions"/>.</param>
    public AuthorizationTransportTransformProvider(
        ICertificateManager certificateManager,
        IOptionsMonitor<AuthorizationTransportOptions> options
    ) {
        _signingCertificate = new AuthorizationTransportSigningCertificate(
            certificateManager,
            options);
        options.OnChange(OptionsOnChange);
        _options = options.CurrentValue;
    }

    /// <summary>
    /// Handles changes to the <see cref="AuthorizationTransportOptions"/>.
    /// </summary>
    /// <param name="options">The updated options.</param>
    /// <param name="name">The name of the options instance.</param>
    private void OptionsOnChange(AuthorizationTransportOptions options, string? name) {
        if (!string.IsNullOrEmpty(name)) { return; }

        _options = options;
    }

    /// <summary>
    /// Validates the cluster configuration for authorization transport.
    /// </summary>
    /// <param name="context">The validation context for the cluster.</param>
    public void ValidateCluster(TransformClusterValidationContext context) {
        if (_options.IsEnabled(context.Cluster)) {
            using (var sharedSigningCredentials = _signingCertificate.GetSigningCredentials()) {
                if (sharedSigningCredentials?.Value is null) {
                    context.Errors.Add(
                        new InvalidOperationException("No signing certificate found."));
                }
            }
        }
    }

    /// <summary>
    /// Validates the route configuration for authorization transport.
    /// </summary>
    /// <param name="context">The validation context for the route.</param>
    public void ValidateRoute(TransformRouteValidationContext context) { }

    /// <summary>
    /// Applies the authorization transport transforms to the given context.
    /// </summary>
    /// <param name="context">The transform builder context.</param>
    public void Apply(TransformBuilderContext context) {
        var requestTransform = new AuthorizationTransportRequestTransform(_options, _signingCertificate);
        context.RequestTransforms.Add(requestTransform);

        var responseTransform = new AuthorizationTransportResponseTransform(_options);
        context.ResponseTransforms.Add(responseTransform);
    }
}
