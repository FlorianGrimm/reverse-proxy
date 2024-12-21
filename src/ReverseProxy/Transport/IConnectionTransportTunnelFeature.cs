// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Transport;

public interface IConnectionTransportTunnelFeature
{
    string? TransportMode { get; }
}

public sealed record ConnectionTransportTunnelFeature(
    string? TransportMode
    ) : IConnectionTransportTunnelFeature;
