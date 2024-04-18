using System;
using System.Net;

namespace Yarp.ReverseProxy.Tunnel;

// This is a .NET 6 workaround for https://github.com/dotnet/aspnetcore/pull/40003 (it's fixed in .NET 7)
public class UriTunnelTransportEndPoint : IPEndPoint
{
    public Uri? Uri { get; }

    public UriTunnelTransportEndPoint(Uri uri) :
        base(0, 0)
    {
        Uri = uri;
    }

    public UriTunnelTransportEndPoint(long address, int port) : base(address, port)
    {
    }

    public override string ToString()
    {
        return Uri?.ToString() ?? base.ToString();
    }
}
