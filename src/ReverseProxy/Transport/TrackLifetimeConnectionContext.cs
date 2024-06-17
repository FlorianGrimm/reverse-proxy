using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// This exists solely to track the lifetime of the connection
/// </summary>
internal class TrackLifetimeConnectionContext : ConnectionContext
{
    private readonly ConnectionContext _connection;
    private readonly TrackLifetimeConnectionContextCollection _connectionCollection;

    public TrackLifetimeConnectionContext(
        ConnectionContext connection,
        TrackLifetimeConnectionContextCollection connectionCollection)
    {
        _connection = connection;
        _connectionCollection = connectionCollection;
    }

    public override string ConnectionId
    {
        get => _connection.ConnectionId;
        set => _connection.ConnectionId = value;
    }

    public override IFeatureCollection Features => _connection.Features;

    public override IDictionary<object, object?> Items
    {
        get => _connection.Items;
        set => _connection.Items = value;
    }

    public override IDuplexPipe Transport
    {
        get => _connection.Transport;
        set => _connection.Transport = value;
    }

    public override EndPoint? LocalEndPoint
    {
        get => _connection.LocalEndPoint;
        set => _connection.LocalEndPoint = value;
    }

    public override EndPoint? RemoteEndPoint
    {
        get => _connection.RemoteEndPoint;
        set => _connection.RemoteEndPoint = value;
    }

    public override CancellationToken ConnectionClosed
    {
        get => _connection.ConnectionClosed;
        set => _connection.ConnectionClosed = value;
    }

    public override void Abort()
    {
        _connection.Abort();
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        _connection.Abort(abortReason);
    }

    public override ValueTask DisposeAsync()
    {
        _connectionCollection.Remove(this);
        return _connection.DisposeAsync();
    }
}
