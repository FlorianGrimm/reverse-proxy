// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Http;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;
internal sealed class TransportTunnelHttp2AuthenticationAnonymous
    : ITransportTunnelHttp2Authentication
{
    public string GetAuthenticationName() => "Anonymous";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
        => new(default(HttpMessageInvoker));

    public ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
        => ValueTask.CompletedTask;
}
