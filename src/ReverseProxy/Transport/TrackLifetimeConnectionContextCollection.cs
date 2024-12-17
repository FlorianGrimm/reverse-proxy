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

public sealed class TrackLifetimeConnectionContextCollection
{
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections;

    public TrackLifetimeConnectionContextCollection(ConcurrentDictionary<ConnectionContext, ConnectionContext> connections)
    {
        _connections = connections;
    }

    public ConnectionContext AddInnerConnection(ConnectionContext connectionContext, AsyncLockOwner connectionLock)
    {
        // Track this connection lifetime
        var trackLifetimeConnectionContext = (ITrackLifetimeConnectionContext)connectionContext;
        if (_connections.TryAdd(connectionContext, connectionContext))
        {
            trackLifetimeConnectionContext.SetTrackLifetime(
                this,
                connectionLock.Transfer(connectionContext));
        }

        return connectionContext;
    }

    public bool TryRemove(ConnectionContext connection)
    {
        return _connections.TryRemove(connection, out _);
    }
}
