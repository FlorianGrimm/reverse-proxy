// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Configuration;

public sealed record TunnelBackendToFrontendConfig
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    public string RemoteTunnelId { get; init; } = default!;

    public int MaxConnectionCount { get; init; } = 10;

    public string Url { get; init; } = default!;

    // WebSocket HTTP2 WebTransport 
    public string Transport { get; init; } = default!;

    public TunnelBackendToFrontendAuthenticationConfig Authentication { get; init; } = default!;

    public string GetRemoteTunnelId()
        =>  (string.IsNullOrEmpty(RemoteTunnelId))
            ? TunnelId
            : RemoteTunnelId;
}

public sealed record TunnelBackendToFrontendAuthenticationConfig
{
}
