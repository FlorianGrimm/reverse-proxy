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

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

public sealed class TunnelConnectionChannelManager
{
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

    public bool TryGetConnectionChannel(string clusterId, [MaybeNullWhen(false)] out TunnelConnectionChannels channels)
    {
        return _clusterConnections.TryGetValue(clusterId, out channels);
    }

    internal void RegisterConnectionChannel(string clusterId)
    {
        if (_clusterConnections.ContainsKey(clusterId)) { return; }

        var result = new TunnelConnectionChannels();
        _clusterConnections.TryAdd(clusterId, result);
    }

    internal void UnregisterConnectionChannel(string clusterId)
    {
        _clusterConnections.TryRemove(clusterId, out _);
    }
}

public sealed class TunnelConnectionChannels : IDisposable
{
    private readonly Channel<TunnelConnectionRequest> _channelTCR;
    private bool _isDisposed;

    public TunnelConnectionChannels()
    {
        _channelTCR = System.Threading.Channels.Channel.CreateUnbounded<TunnelConnectionRequest>();
    }

    public ChannelWriter<TunnelConnectionRequest> Writer
    {
        get
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(TunnelConnectionChannels));
            }
            return _channelTCR.Writer;
        }
    }

    public ChannelReader<TunnelConnectionRequest> Reader
    {
        get
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(TunnelConnectionChannels));
            }
            return _channelTCR.Reader;
        }
    }

    // TODO: replace it with proper monitoring
    public int CountSource;
    public int CountSink;

    public void Dispose()
    {
        _isDisposed = true;
    }
}

public sealed class TunnelConnectionRequest(ILogger logger)
    : IDisposable
    /* IResettable */
{
    private static long _nextId = 0;
    private readonly long _id = System.Threading.Interlocked.Increment(ref _nextId);
    private readonly ILogger _logger = logger;
    private SemaphoreSlim _lock = new(0, 1);
    private Stream? _stream;
    private bool _isDisposed;

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

    public TunnelConnectionRequest? GetReseted()
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

    public bool TryReset() {
        if (_isDisposed || _stream is not null || _lock.CurrentCount != 0)
        {
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


    public sealed class TCRPooledObjectPolicy(ILogger logger)
        : PooledObjectPolicy<TunnelConnectionRequest>()
    {
        private readonly ILogger _logger = logger;

        public override TunnelConnectionRequest Create() => new TunnelConnectionRequest(_logger);

        public override bool Return(TunnelConnectionRequest obj) => obj.TryReset();
    }
}
