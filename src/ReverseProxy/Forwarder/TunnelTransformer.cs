// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

namespace Yarp.ReverseProxy.Forwarder;

public class TunnelTransformer
{
    public static readonly TunnelTransformer Empty = new TunnelTransformer();

    public virtual ValueTask TunnelTransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix, CancellationToken cancellationToken)
    {
        return new();
    }

    /* 

    public virtual ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse) {}
    public virtual ValueTask TransformResponseTrailersAsync(HttpContext httpContext, HttpResponseMessage proxyResponse, CancellationToken cancellationToken)

    */
}
