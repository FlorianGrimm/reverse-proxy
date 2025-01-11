// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

using Microsoft.AspNetCore.Connections;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public interface ITrackLifetimeConnectionContext
{
    void SetTrackLifetime(
        TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection,
        AsyncLockOwner asyncLockOwner);
}

/// <summary>
/// Collection of connections that are tracked for lifetime management.
/// </summary>
public sealed class TrackLifetimeConnectionContextCollection
{
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections;

    /// <summary>
    /// Initializes a new instance of the <see cref="TrackLifetimeConnectionContextCollection"/> class.
    /// </summary>
    /// <param name="connections">The connections to manage</param>
    public TrackLifetimeConnectionContextCollection(ConcurrentDictionary<ConnectionContext, ConnectionContext> connections)
    {
        _connections = connections;
    }

    /// <summary>
    /// Adds a connection to the collection.
    /// </summary>
    /// <param name="connectionContext"></param>
    /// <param name="connectionLock"></param>
    public void AddInnerConnection(ConnectionContext connectionContext, AsyncLockOwner connectionLock)
    {
        // Track this connection lifetime
        if (connectionContext is ITrackLifetimeConnectionContext trackLifetimeConnectionContext)
        {
            if (_connections.TryAdd(connectionContext, connectionContext))
            {
                trackLifetimeConnectionContext.SetTrackLifetime(
                    this,
                    connectionLock.Transfer(connectionContext));
            }
        }
    }

    public bool TryRemove(ConnectionContext connection)
    {
        return _connections.TryRemove(connection, out _);
    }
}
