using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading.Channels;

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

        var result = new TunnelConnectionChannels(Channel.CreateUnbounded<int>(), Channel.CreateUnbounded<Stream>());
        _clusterConnections.TryAdd(clusterId, result);
    }
}

public sealed record TunnelConnectionChannels(
    Channel<int> Trigger,
    Channel<Stream> Streams
    )
{
    public int CountSource;
    public int CountSink;
}
