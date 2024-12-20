// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable IDE0058 // Expression value is never used

using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// Manages tunnel connection channels for clusters.
/// </summary>
public sealed partial class TunnelConnectionChannelManager
{
    public static void RegisterTunnelConnectionChannelManagerTunnel(IServiceCollection services)
    {
        services.TryAddSingleton<TunnelConnectionChannelManager, TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITunnelChangeListener, TunnelChangeListener>());
    }

    public static void RegisterTunnelConnectionChannelManagerCluster(IServiceCollection services)
    {
        services.TryAddSingleton<TunnelConnectionChannelManager, TunnelConnectionChannelManager>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IClusterChangeListener, ClusterChangeListener>());
    }

    internal sealed class TunnelChangeListener(TunnelConnectionChannelManager manager) : ITunnelChangeListener
    {
        public void OnTunnelAdded(TunnelState tunnel)
        {
            if (tunnel.Model.Config.IsTunnelTransport())
            {
                manager.RegisterConnectionChannel(tunnel.TunnelId);
            }
        }

        public void OnTunnelChanged(TunnelState tunnel)
        {
            if (tunnel.Model.Config.IsTunnelTransport())
            {
                manager.RegisterConnectionChannel(tunnel.TunnelId);
            }
        }

        public void OnTunnelRemoved(TunnelState tunnel)
        {
            if (tunnel.Model.Config.IsTunnelTransport())
            {
                manager.UnregisterConnectionChannel(tunnel.TunnelId);
            }
        }
    }

    // calls the manager's RegisterConnectionChannel or UnregisterConnectionChannel on cluster changes
    internal sealed class ClusterChangeListener(TunnelConnectionChannelManager manager) : IClusterChangeListener
    {
        public void OnClusterAdded(ClusterState cluster)
        {
            if (cluster.Model.Config.IsTunnelTransport())
            {
                manager.RegisterConnectionChannel(cluster.ClusterId);
            }
        }

        public void OnClusterChanged(ClusterState cluster)
        {
            if (cluster.Model.Config.IsTunnelTransport())
            {
                manager.RegisterConnectionChannel(cluster.ClusterId);
            }
        }

        public void OnClusterRemoved(ClusterState cluster)
        {
            if (cluster.Model.Config.IsTunnelTransport())
            {
                manager.UnregisterConnectionChannel(cluster.ClusterId);
            }
        }
    }

    private readonly ConcurrentDictionary<string, TunnelConnectionChannels> _clusterConnections = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Tries to get the connection channels for a given cluster.
    /// </summary>
    /// <param name="clusterId">The cluster ID.</param>
    /// <param name="channels">The connection channels.</param>
    /// <returns>True if the connection channels were found; otherwise, false.</returns>
    public bool TryGetConnectionChannel(string clusterId, [MaybeNullWhen(false)] out TunnelConnectionChannels channels)
    {
        return _clusterConnections.TryGetValue(clusterId, out channels);
    }

    /// <summary>
    /// Registers connection channels for a given cluster.
    /// </summary>
    /// <param name="clusterId">The cluster ID.</param>
    public void RegisterConnectionChannel(string clusterId)
    {
        if (_clusterConnections.ContainsKey(clusterId)) { return; }

        var result = new TunnelConnectionChannels();
        _clusterConnections.TryAdd(clusterId, result);
    }

    /// <summary>
    /// Unregisters connection channels for a given cluster.
    /// </summary>
    /// <param name="clusterId">The cluster ID.</param>
    public void UnregisterConnectionChannel(string clusterId)
    {
        _clusterConnections.TryRemove(clusterId, out _);
    }
}

/// <summary>
/// Represents the connection channels for a tunnel.
/// </summary>
public sealed class TunnelConnectionChannels : IDisposable
{
    private readonly Channel<TunnelConnectionRequest> _channelTunnelConnectionRequest;
    private bool _isDisposed;

    public TunnelConnectionChannels()
    {
        _channelTunnelConnectionRequest = System.Threading.Channels.Channel.CreateUnbounded<TunnelConnectionRequest>();
    }

    /// <summary>
    /// Gets the writer for the connection requests.
    /// </summary>
    public ChannelWriter<TunnelConnectionRequest> Writer
    {
        get
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(TunnelConnectionChannels));
            }
            return _channelTunnelConnectionRequest.Writer;
        }
    }

    /// <summary>
    /// Gets the reader for the connection requests.
    /// </summary>
    public ChannelReader<TunnelConnectionRequest> Reader
    {
        get
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(TunnelConnectionChannels));
            }
            return _channelTunnelConnectionRequest.Reader;
        }
    }

    // TODO: replace it with proper monitoring
    public int CountSource;
    public int CountSink;

    /// <summary>
    /// Disposes the connection channels.
    /// </summary>
    public void Dispose()
    {
        _isDisposed = true;
    }
}

/// <summary>
/// Represents a stream for a tunnel connection.
/// </summary>
public sealed partial class TunnelConnectionRequest(ILogger logger)
    : IDisposable
/* IResettable */
{
    private static long _nextId = 0;
    private readonly long _id = System.Threading.Interlocked.Increment(ref _nextId);
    private readonly ILogger _logger = logger;
    private SemaphoreSlim _lock = new(0, 1);
    private Stream? _stream;
    private bool _isDisposed;

    /// <summary>
    /// Sets the stream for the connection request.
    /// The stream is return by <see cref="GetStreamAsync(CancellationToken)"/>.
    /// </summary>
    /// <param name="stream">The stream.</param>
    /// <returns>True if the stream was set; otherwise, false.</returns>
    public bool SetStream(Stream stream)
    {
        if (_isDisposed)
        {
            return false;
        }
        else
        {
            System.Threading.Interlocked.Exchange(ref _stream, stream);
            _lock.Release();
            return true;
        }
    }

    /// <summary>
    /// Gets the stream for the connection request asynchronously.
    /// It waits until the stream is set by <see cref="SetStream(Stream)"/>.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The stream.</returns>
    public async Task<Stream?> GetStreamAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _lock.WaitAsync(cancellationToken);
            return System.Threading.Interlocked.Exchange(ref _stream, null);
        }
        catch
        {
            _isDisposed = true;
            return null;
        }
    }

    /// <summary>
    /// Gets this reset instance - or null.
    /// </summary>
    /// <returns>The reset connection request - or null.</returns>
    public TunnelConnectionRequest? GetIfReusable()
    {
        if (_isDisposed || _stream is not null || _lock.CurrentCount != 0)
        {
            Dispose();
            return null;
        }
        else
        {
            return this;
        }
    }

    /// <summary>
    /// Handles the <see cref="IPooledObjectPolicy{T}.Return(T)"/> calls.
    /// </summary>
    /// <returns><see langword="true" /> if the object should be returned to the pool. <see langword="false" /> if it's not possible/desirable for the pool to keep the object.</returns>
    public bool HandlePoolingReturn()
    {
        // if the stream is set then the object is not reusable - since it's seams to be in use -.
        if (_isDisposed || _stream is not null || _lock.CurrentCount != 0)
        {
            // When does this happen?
            // I assume the inner request need too much time and the outer request timed out or was canceled.
            // Or GetStreamAsync was called / SetStream not / shutdown?.
            // So Dispose is the right thing to do here.
            Dispose();
            return false;
        }
        else
        {
            return true;
        }
    }

    public void Failed()
    {
        Dispose();
    }

    private void Dispose(bool disposing)
    {
        using (var l = _lock)
        {
            // the stream's owner is not this - so no Dispose here.
            _isDisposed = true;
            if (disposing)
            {
                _stream = null;
                _lock = null!;
            }
        }
    }

    ~TunnelConnectionRequest()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Represents a policy for managing pooled objects.
    /// </summary>
    public sealed class TCRPooledObjectPolicy(ILogger logger)
        : PooledObjectPolicy<TunnelConnectionRequest>()
    {
        private readonly ILogger _logger = logger;

        /// <summary>
        /// Create a <see cref="TunnelConnectionRequest"/>.
        /// </summary>
        /// <returns>The <see cref="TunnelConnectionRequest"/> which was created.</returns>
        public override TunnelConnectionRequest Create() => new TunnelConnectionRequest(_logger);

        /// <summary>
        /// Runs some processing when an object was returned to the pool. Can be used to reset the state of an object and indicate if the object should be returned to the pool.
        /// </summary>
        /// <param name="obj">The object to return to the pool.</param>
        /// <returns><see langword="true" /> if the object should be returned to the pool. <see langword="false" /> if it's not possible/desirable for the pool to keep the object.</returns>

        public override bool Return(TunnelConnectionRequest obj)
        {
            var result = obj.HandlePoolingReturn();
            if (!result)
            {
                Log.TunnelConnectionRequestIsNotReusable(_logger, obj);
            }
            return result;
        }
    }

    internal static partial class Log
    {
        private static readonly Action<ILogger, long, Exception?> _tunnelConnectionRequestIsNotReusable = LoggerMessage.Define<long>(
            LogLevel.Debug,
            EventIds.TunnelConnectionRequestIsNotReusable,
            "TunnelConnectionRequest with ID {RequestId} is not reusable.");

        public static void TunnelConnectionRequestIsNotReusable(ILogger logger, TunnelConnectionRequest obj)
        {
            _tunnelConnectionRequestIsNotReusable(logger, obj._id, null);
        }
    }
}
