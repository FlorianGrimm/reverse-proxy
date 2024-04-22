using System;
using System.IO;
using System.Threading.Channels;

namespace Yarp.ReverseProxy.Tunnel;

public sealed record class TunnelConnectionChannel(
    string ConnectionChannelId,
    string TunnelId,
    string Address,
    Channel<int> Requests,
    Channel<Stream> Responses
    )
{
    public static TunnelConnectionChannel Create(
        string host
        ) {
        var connectionChannelId = Guid.NewGuid().ToString();
        var tunnelId = host.Split('-')[0];
        string address;

        if (host.StartsWith("https://") || host.StartsWith("http://") || host.Contains("://"))
        {
            // TODO: not sure if this is correct since I expect the host without protocol, but if so the question is what about https: it might work since the host may life in different networks (Azure - OnPrem, DMZ - Inner)
            address = host;
        }
        else
        {
            // TODO: this is a guess, but I think it should be correct, since the tunnel is already established with https??
            address = "http://" + host;
        }

        return new TunnelConnectionChannel(connectionChannelId, tunnelId, address, Channel.CreateUnbounded<int>(), Channel.CreateUnbounded<Stream>());
    }

    public bool IsFirstRequest;

    public int Count = 0;

    public bool IsClosed => Count == 0;
}
