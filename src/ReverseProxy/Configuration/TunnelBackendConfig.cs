// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Configuration;

public sealed record TunnelBackendConfig
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;

    public int MaxConnectionCount { get; init; } = 10;

    public string Transport { get; init; } = default!;
}
