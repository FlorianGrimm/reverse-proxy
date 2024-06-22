using System.Collections.Concurrent;
using System.Threading;

using Microsoft.AspNetCore.Connections;

namespace Yarp.ReverseProxy.Transport;

internal interface ITrackLifetimeConnectionContext
{
    void SetTracklifetime(TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection);
}

internal sealed class TrackLifetimeConnectionContextCollection
{
    // is owned by the owner TunnelXyzConnectionListener
    private readonly SemaphoreSlim _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections;

    public TrackLifetimeConnectionContextCollection(ConcurrentDictionary<ConnectionContext, ConnectionContext> connections, SemaphoreSlim connectionLock)
    {
        _connections = connections;
        _connectionLock = connectionLock;
    }
    internal ConnectionContext AddInnerConnection(ConnectionContext connectionContext)
    {
        //var connection = new TrackLifetimeConnectionContext(innerConnection, this);

        // Track this connection lifetime
        var trackLifetimeConnectionContext = (ITrackLifetimeConnectionContext)connectionContext;
        if (_connections.TryAdd(connectionContext, connectionContext))
        {
            trackLifetimeConnectionContext.SetTracklifetime(this);
        }

        return connectionContext;
    }

    internal void Remove(ConnectionContext connection)
    {
        if (_connections.TryRemove(connection, out _))
        {
            _connectionLock.Release();
        }
    }
}
