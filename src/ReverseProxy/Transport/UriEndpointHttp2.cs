using System;
using System.Net;

namespace Yarp.ReverseProxy.Transport;

// This is a .NET 6 workaround for https://github.com/dotnet/aspnetcore/pull/40003 (it's fixed in .NET 7)
public sealed class UriEndPointHttp2 : IPEndPoint
{
    public Uri? Uri { get; }

    public UriEndPointHttp2(Uri uri) :
        this(0, 0)
    {
        Uri = uri;
    }

    public UriEndPointHttp2(long address, int port) : base(address, port)
    {
    }

    public static implicit operator UriEndPointHttp2(Uri uri)
    {
        return new UriEndPointHttp2(uri);
    }
}
