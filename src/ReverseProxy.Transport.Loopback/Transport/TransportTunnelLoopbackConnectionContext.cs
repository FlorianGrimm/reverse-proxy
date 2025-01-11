// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelLoopbackConnectionContext
    : ConnectionContext
    , IConnectionLifetimeFeature
    , IConnectionEndPointFeature
    , IConnectionItemsFeature
    , IConnectionIdFeature
    , IConnectionTransportFeature
    , IConnectionTransportTunnelFeature
    , IDuplexPipe
    , ITrackLifetimeConnectionContext
{
    private static readonly ConnectionTransportTunnelFeature _connectionTransportTunnelFeature = new(TransportTunnelLoopbackConstants.TransportNameTunnelLoopback);

    internal static (TransportTunnelLoopbackConnectionContext connectionContext, Stream stream) Create(ILogger logger)
    {
        var connectionContext = new TransportTunnelLoopbackConnectionContext(logger);
        var streamClient = new TransportTunnelLoopbackClientStream(connectionContext, logger);
        return (connectionContext, streamClient);
    }

    private readonly TaskCompletionSource _executionTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ILogger _logger;

    private TrackLifetimeConnectionContextCollection? _trackLifetimeConnectionContextCollection;
    private AsyncLockOwner _asyncLockOwner;

    private TransportTunnelLoopbackConnectionContext(ILogger logger)
    {
        Transport = this;

        Features.Set<IConnectionIdFeature>(this);
        Features.Set<IConnectionTransportFeature>(this);
        Features.Set<IConnectionItemsFeature>(this);
        Features.Set<IConnectionEndPointFeature>(this);
        Features.Set<IConnectionLifetimeFeature>(this);
        Features.Set<IConnectionTransportTunnelFeature>(_connectionTransportTunnelFeature);
        Items.Add(typeof(IConnectionTransportTunnelFeature), _connectionTransportTunnelFeature);
        _logger = logger;

        PipeRequest = new Pipe();
        PipeResponse = new Pipe();

        Input = PipeRequest.Reader;
        Output = PipeResponse.Writer;
    }

    public string? TransportMode => TransportTunnelLoopbackConstants.TransportNameTunnelLoopback;

    public Pipe PipeRequest { get; }
    public Pipe PipeResponse { get; }

    public Task ExecutionTask => _executionTcs.Task;

    public override string ConnectionId { get; set; } = Guid.NewGuid().ToString();

    public override IFeatureCollection Features { get; } = new FeatureCollection();

    public override IDictionary<object, object?> Items { get; set; } = new ConnectionItems();

    public override IDuplexPipe Transport { get; set; }

    public override EndPoint? LocalEndPoint { get; set; }

    public override EndPoint? RemoteEndPoint { get; set; }

    public PipeReader Input { get; set; }

    public PipeWriter Output { get; set; }

    public override CancellationToken ConnectionClosed { get; set; }

    public void SetTrackLifetime(
        TrackLifetimeConnectionContextCollection trackLifetimeConnectionContextCollection,
        AsyncLockOwner asyncLockOwner)
    {
        _trackLifetimeConnectionContextCollection = trackLifetimeConnectionContextCollection;
        _asyncLockOwner = asyncLockOwner;
    }

    public override void Abort()
    {
        var releasedLock = _asyncLockOwner.Release();
        var removedFromCollection = _trackLifetimeConnectionContextCollection?.TryRemove(this) ?? false;
        _executionTcs?.TrySetCanceled();
        Input?.CancelPendingRead();
        Output?.CancelPendingFlush();
        System.Diagnostics.Debug.Assert(releasedLock == removedFromCollection);
    }

    public override void Abort(ConnectionAbortedException abortReason)
    {
        Abort();
    }

    public override ValueTask DisposeAsync()
    {
        Abort();

        return base.DisposeAsync();
    }
}
