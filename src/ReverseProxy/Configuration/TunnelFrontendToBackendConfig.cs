// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Configuration;

/// <summary>
/// TODO
/// </summary>
public sealed record TunnelFrontendToBackendConfig
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;


    // WebSocket HTTP2 WebTransport 
    public string Transport { get; init; } = default!;

    // TODO: public List<string> AllowedOrigins
    
    /// <summary>
    /// Big TODO
    /// </summary>
    public TunnelFrontendToBackendAuthenticationConfig Authentication { get; init; } = default!;
}

public sealed record TunnelFrontendToBackendAuthenticationConfig
{
}
