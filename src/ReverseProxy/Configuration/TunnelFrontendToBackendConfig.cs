// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Configuration;

public sealed record TunnelFrontendToBackendConfig
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    public TunnelFrontendToBackendAuthenticationConfig Authentication { get; init; } = default!;

    //public List<string> AllowedDest

    // WebSocket HTTP2 WebTransport 
    public string Transport { get; init; } = default!;
}
public sealed record TunnelFrontendToBackendAuthenticationConfig
{
}
