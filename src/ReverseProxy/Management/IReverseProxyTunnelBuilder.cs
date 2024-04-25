// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Reverse Proxy tunnel builder interface.
/// </summary>
public interface IReverseProxyTunnelBuilder
{
    /// <summary>
    /// Gets the services.
    /// </summary>
    IServiceCollection Services { get; }
}
