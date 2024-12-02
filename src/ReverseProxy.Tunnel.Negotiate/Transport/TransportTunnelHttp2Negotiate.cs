// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

/*
    The Windows Authentication is not supported by the HTTP/2 protocol.
    The Windows Authentication is supported by the HTTP/1.1 protocol.
    So the authentication is done by the HTTP/1.1 protocol (and a cookie is set)
    and then the HTTP/2 protocol is used for the data (and the cookie is used for authentication).
*/
internal sealed class TransportTunnelHttp2Negotiate
    : ITransportTunnelHttp2Authenticator
{
    private readonly ConcurrentDictionary<string, PerTunnel> _perTunnel = new(StringComparer.CurrentCultureIgnoreCase);
    private readonly ILogger<TransportTunnelHttp2Negotiate> _logger;

    public TransportTunnelHttp2Negotiate(
        ILogger<TransportTunnelHttp2Negotiate> logger
        )
    {
        _logger = logger;
    }

    public string GetAuthenticationName() => "Negotiate";

    private PerTunnel GetPerTunnel(string key)
    {
        while (true)
        {
            if (_perTunnel.TryGetValue(key, out var result))
            {
                return result;
            }
            result = new PerTunnel(_logger);
            if (_perTunnel.TryAdd(key, result))
            {
                return result;
            }
        }
    }

    public async ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var perTunnel = GetPerTunnel(tunnel.TunnelId);
        return await perTunnel.ConfigureSocketsHttpHandlerAsync(socketsHttpHandler);
    }

    public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        var perTunnel = GetPerTunnel(tunnel.TunnelId);
        await perTunnel.ConfigureHttpRequestMessageAsync(requestMessage);
    }

    internal sealed class PerTunnel(ILogger logger)
    {
        private readonly ILogger _logger = logger;
        private readonly CookieContainer _cookieContainer = new();

        public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(SocketsHttpHandler socketsHttpHandler)
        {
            socketsHttpHandler.CookieContainer = _cookieContainer;
            return new(new HttpMessageInvoker(socketsHttpHandler));
        }

        public async ValueTask ConfigureHttpRequestMessageAsync(HttpRequestMessage requestMessage)
        {
            try
            {
                if (requestMessage.RequestUri is not { } requestUri)
                {
                    throw new ArgumentException("RequestUri is null", nameof(requestMessage));
                }
                using SocketsHttpHandler socketsHttpHandlerAuth = new();
                socketsHttpHandlerAuth.Credentials = System.Net.CredentialCache.DefaultCredentials;
                socketsHttpHandlerAuth.CookieContainer = _cookieContainer;
                using var requestMessageAuth = new HttpRequestMessage()
                {
                    Version = new Version(1, 1),
                    RequestUri = requestUri,
                    Method = HttpMethod.Get
                };
                using var httpMessageInvokerAuth = new HttpMessageInvoker(socketsHttpHandlerAuth);
                using var responseMessage = await httpMessageInvokerAuth.SendAsync(requestMessageAuth, CancellationToken.None);
                if (responseMessage.IsSuccessStatusCode)
                {
                    _ = await responseMessage.Content.ReadAsStringAsync();
                    if (_logger.IsEnabled(LogLevel.Information))
                    {
                        // _logger.LogInformation("Authenticator HTTP2 Tunnel: {RequestUri} success", requestMessageAuth.RequestUri);
                        _logger.LogInformation("Authenticated HTTP2 Tunnel: {RequestUri} success {cookie}", requestMessageAuth.RequestUri, _cookieContainer.GetCookieHeader(requestUri));
                    }
                }
                else
                {
                    _logger.LogWarning("Authenticator HTTP2 Tunnel: {RequestUri} failed.", requestMessageAuth.RequestUri);
                }

                
            }
            catch (Exception error)
            {
                _logger.LogError(error, "Authenticator HTTP2 Tunnel: {RequestUri} failed", requestMessage.RequestUri);
                throw;
            }
        }
    }
}
