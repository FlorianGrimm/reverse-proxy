using System.Collections.Concurrent;
using System.Threading;

using Microsoft.AspNetCore.Connections;

namespace Yarp.ReverseProxy.Transport;

internal class TrackLifetimeConnectionContextCollection
{
    // is owned by the owner TunnelXyzConnectionListener
    private readonly SemaphoreSlim _connectionLock;
    private readonly ConcurrentDictionary<ConnectionContext, ConnectionContext> _connections;

    public TrackLifetimeConnectionContextCollection(ConcurrentDictionary<ConnectionContext, ConnectionContext> connections, SemaphoreSlim connectionLock)
    {
        _connections = connections;
        _connectionLock = connectionLock;
    }

    //internal void Add(TrackLifetimeConnectionContext connection)
    //{
    //    _connections.TryAdd(connection, connection);
    //}

    internal TrackLifetimeConnectionContext AddInnerConnection(ConnectionContext innerConnection)
    {
        var connection = new TrackLifetimeConnectionContext(innerConnection, this);

        // Track this connection lifetime
        _connections.TryAdd(connection, connection);
        
        return connection;
    }

    internal void Remove(TrackLifetimeConnectionContext connection)
    {
        if (_connections.TryRemove(connection, out _)) {
            _connectionLock.Release();
        }
    }
}
