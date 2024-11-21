// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net;

namespace Yarp.ReverseProxy.Transport;

public sealed class UriEndPointHttp2(
        Uri uri,
        string tunnelId
    ) : IPEndPoint(0, 0)
{
    public Uri Uri { get; } = uri;

    public string TunnelId { get; } = tunnelId;

    public override string ToString() => $"{Uri}#{TunnelId}";
}
