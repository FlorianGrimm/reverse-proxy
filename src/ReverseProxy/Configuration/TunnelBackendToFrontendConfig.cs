// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Yarp.ReverseProxy.Forwarder;

namespace Yarp.ReverseProxy.Configuration;

public sealed record TunnelBackendToFrontendConfig
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    /// <summary>
    /// The TunnelId on the remote / frontend.
    /// </summary>
    public string? RemoteTunnelId { get; init; }


    /// <summary>
    /// Default %ComputerName% - if you have security concerns, you can set this to a specific hostname.
    /// </summary>
    public string? Hostname { get; init; }

    public int MaxConnectionCount { get; init; } = 10;

    public string Url { get; init; } = default!;

    // WebSocket HTTP2 WebTransport 
    public string Transport { get; init; } = ForwarderTunnelHTTP2ClientFactory.Transport;

    public TunnelBackendToFrontendAuthenticationConfig Authentication { get; init; } = default!;

    //public string GetRemoteTunnelId()
    //    =>  (string.IsNullOrEmpty(RemoteTunnelId))
    //        ? TunnelId
    //        : RemoteTunnelId;
}

public sealed record TunnelBackendToFrontendAuthenticationConfig
{
}
