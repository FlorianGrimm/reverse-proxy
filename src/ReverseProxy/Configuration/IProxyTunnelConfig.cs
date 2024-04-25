// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Configuration;

/// <summary>
/// Represents a snapshot of proxy configuration data. These properties may be accessed multiple times and should not be modified.
/// </summary>
public interface IProxyTunnelConfig
{    
    private static readonly ConditionalWeakTable<IProxyTunnelConfig, string> _revisionIdsTable = new();

    /// <summary>
    /// A unique identifier for this revision of the configuration.
    /// </summary>
    string RevisionId => _revisionIdsTable.GetValue(this, static _ => Guid.NewGuid().ToString());

    IReadOnlyList<TunnelFrontendToBackendConfig> TunnelFrontendToBackends { get; }
    IReadOnlyList<TunnelBackendToFrontendConfig> TunnelBackendToFrontends { get; }

    /// <summary>
    /// A notification that triggers when this snapshot expires.
    /// </summary>
    IChangeToken ChangeToken { get; }
}
