using System;
using System.Net;

namespace Yarp.ReverseProxy.Tunnel.Transport;

// This is a .NET 6 workaround for https://github.com/dotnet/aspnetcore/pull/40003 (it's fixed in .NET 7)
internal class UriEndPoint2 : IPEndPoint
{
    public Uri? Uri { get; }

    public UriEndPoint2(Uri uri) :
        this(0, 0)
    {
        Uri = uri;
    }

    public UriEndPoint2(long address, int port) : base(address, port)
    {
    }
}
