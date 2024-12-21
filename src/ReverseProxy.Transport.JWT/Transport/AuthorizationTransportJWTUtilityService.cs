using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Security.Claims;

using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Service for handling JWT token creation and authorization header setting.
/// </summary>
public sealed class AuthorizationTransportJWTUtilityService {
    private readonly AuthorizationTransportSigningCertificate _signingCertificate;
    private AuthorizationTransportOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationTransportJWTUtilityService"/> class.
    /// </summary>
    /// <param name="certificateManager">The certificate manager.</param>
    /// <param name="options">The options monitor for <see cref="AuthorizationTransportOptions"/>.</param>
    public AuthorizationTransportJWTUtilityService(
        ICertificateManager certificateManager,
        IOptionsMonitor<AuthorizationTransportOptions> options) {
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
    /// Creates a <see cref="ClaimsIdentity"/> for the JWT token from the inbound user.
    /// </summary>
    /// <param name="inboundUser">The inbound user principal.</param>
    /// <returns>A <see cref="ClaimsIdentity"/> for the JWT token, or null if the inbound user is null.</returns>
    [return: NotNullIfNotNull(nameof(inboundUser))]
    public ClaimsIdentity? CreateJWTClaimsIdentity(
        ClaimsPrincipal? inboundUser)
        => AuthorizationTransportJWTUtility.CreateJWTClaimsIdentity(inboundUser, _options);

    /// <summary>
    /// Creates a JWT token from the specified claims identity.
    /// </summary>
    /// <param name="outboundClaimsIdentity">The claims identity for the JWT token.</param>
    /// <returns>The created JWT token.</returns>
    /// <exception cref="InvalidOperationException">Thrown if no signing credentials are available.</exception>
    public string CreateJWTToken(ClaimsIdentity outboundClaimsIdentity) {
        using (var shareSigningCredentials = _signingCertificate.GetSigningCredentials()) {
            if (!(shareSigningCredentials?.Value is { } certificate)) {
                throw new InvalidOperationException("No signing credentials available.");
            }
            return AuthorizationTransportJWTUtility.CreateJWTToken(outboundClaimsIdentity, certificate, _options);
        }
    }

    /// <summary>
    /// Sets the Authorization header with a JWT token for the specified user.
    /// </summary>
    /// <param name="user">The user for whom the JWT token is created.</param>
    /// <param name="requestMessage">The HTTP request message to which the Authorization header is added.</param>
    /// <returns>True if the Authorization header was set; otherwise, false.</returns>
    public bool SetAuthorizationHeaderWithUserAasJwtToken(ClaimsPrincipal user, HttpRequestMessage requestMessage) {
        if (CreateJWTClaimsIdentity(user) is { } jwtClaimsIdentity) {
            var jwtToken = CreateJWTToken(jwtClaimsIdentity);
            requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwtToken);
            return true;
        }
        return false;
    }
}
