// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Configuration;

public sealed record TunnelFrontendConfig
{
    /// <summary>
    /// The Id for this tunnel.
    /// </summary>
    public string TunnelId { get; init; } = default!;
}
