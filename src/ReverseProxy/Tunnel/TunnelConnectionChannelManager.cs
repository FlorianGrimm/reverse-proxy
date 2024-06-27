// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

public sealed class TunnelConnectionChannelManager
{
    internal sealed class ClusterChangeListener(TunnelConnectionChannelManager manager) : IClusterChangeListener
    {
        public void OnClusterAdded(ClusterState cluster)
        {
            manager.RegisterConnectionChannel(cluster.ClusterId);
        }

        public void OnClusterChanged(ClusterState cluster)
        {
        }

        public void OnClusterRemoved(ClusterState cluster)
        {
            manager._clusterConnections.TryRemove(cluster.ClusterId, out _);
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
}

public sealed class TunnelConnectionChannels : IDisposable
{
    private readonly Channel<TunnelConnectionRequest> _channelTCR;
    private bool _isDisposed;

    internal TunnelConnectionChannels()
    {
        _channelTCR = System.Threading.Channels.Channel.CreateUnbounded<TunnelConnectionRequest>();
    }

    internal ChannelWriter<TunnelConnectionRequest> Writer
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

    internal ChannelReader<TunnelConnectionRequest> Reader
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

    // TODO: replace it with propper monitoring
    public int CountSource;
    public int CountSink;

    public void Dispose()
    {
        _isDisposed = true;
    }
}

internal sealed class TunnelConnectionRequest()
    : IDisposable
{
    private SemaphoreSlim _lock = new(0, 1);
    private Stream? _stream;
    private bool _isDisposed;

    internal bool Write(Stream stream)
    {
        if (_isDisposed)
        {
            return false;
        }
        else
        {
            _stream = stream;
            _lock.Release();
            return true;
        }
    }

    internal async Task<Stream?> ReadAsync(CancellationToken cancellationToken)
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

    internal TunnelConnectionRequest? GetReseted()
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

    internal void Failed()
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
}
