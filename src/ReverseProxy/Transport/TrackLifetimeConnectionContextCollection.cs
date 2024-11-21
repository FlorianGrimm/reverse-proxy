// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;

using Microsoft.AspNetCore.Connections;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal interface ITrackLifetimeConnectionContext
{
    void SetTracklifetime(
        TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection,
        AsyncLockOwner asyncLockOwner);
}

internal sealed class TrackLifetimeConnectionContextCollection
{
    // is owned by the owner TunnelXyzConnectionListener
    private readonly AsyncLockWithOwner _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections;

    public TrackLifetimeConnectionContextCollection(ConcurrentDictionary<ConnectionContext, ConnectionContext> connections, AsyncLockWithOwner connectionLock)
    {
        _connections = connections;
        _connectionLock = connectionLock;
    }

    internal ConnectionContext AddInnerConnection(ConnectionContext connectionContext, AsyncLockOwner connectionLock)
    {
        // Track this connection lifetime
        var trackLifetimeConnectionContext = (ITrackLifetimeConnectionContext)connectionContext;
        if (_connections.TryAdd(connectionContext, connectionContext))
        {
            trackLifetimeConnectionContext.SetTracklifetime(
                this,
                connectionLock.Transfer(connectionContext));
        }

        return connectionContext;
    }

    internal bool TryRemove(ConnectionContext connection)
    {
        return _connections.TryRemove(connection, out _);
    }
}
