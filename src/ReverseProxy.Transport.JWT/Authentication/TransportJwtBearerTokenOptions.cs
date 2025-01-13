// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;

using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Authentication;

public class TransportJwtBearerTokenOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets a single valid audience value for any received token.
    /// </summary>
    /// <value>
    /// The expected audience for any received token.
    /// </value>
    public string? Audience { get; set; }

    /// <summary>
    /// Gets or sets the <see cref="IEnumerable{String}"/> that contains valid issuers that will be used to check against the token's issuer.
    /// The default is <c>null</c>.
    /// </summary>
    public IEnumerable<string> ValidIssuers { get; set; } = [];

    /// <summary>
    /// Gets or sets the algorithm used for signing the token. Default is RsaSha256
    /// </summary>
    public string Algorithm { get; set; } = SecurityAlgorithms.RsaSha256;

    /// <summary>
    /// Gets or sets the secret for a SymmetricSecurityKey.
    /// </summary>
    public string? SigningKeySecret { get; set; }

    /// <summary>
    /// Gets or sets the configuration for the signing certificate.
    /// </summary>
    public string? SigningCertificate { get; set; }

    /// <summary>
    /// Gets or sets the function to create the SecurityKey
    /// </summary>
    public Func<SecurityKey>? CreateSecurityKey { get; set; }

}
