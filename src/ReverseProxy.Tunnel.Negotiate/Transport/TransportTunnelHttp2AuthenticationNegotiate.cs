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
    and then the HTTP/2 protocol is used for the data (and the cookie is used for authn).
*/
internal sealed class TransportTunnelHttp2AuthenticationNegotiate
    : ITransportTunnelHttp2Authentication
{
    private readonly ConcurrentDictionary<string, PerTunnel> _perTunnel = new(StringComparer.CurrentCultureIgnoreCase);
    private readonly ILogger<TransportTunnelHttp2AuthenticationNegotiate> _logger;

    public TransportTunnelHttp2AuthenticationNegotiate(
        ILogger<TransportTunnelHttp2AuthenticationNegotiate> logger
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
            //socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
            socketsHttpHandler.CookieContainer = _cookieContainer;
            return new(new HttpMessageInvoker(socketsHttpHandler));
        }

        public async ValueTask ConfigureHttpRequestMessageAsync(HttpRequestMessage requestMessage)
        {
            try
            {
                using SocketsHttpHandler socketsHttpHandlerAuth = new();
                socketsHttpHandlerAuth.Credentials = System.Net.CredentialCache.DefaultCredentials;
                socketsHttpHandlerAuth.CookieContainer = _cookieContainer;
                using var requestMessageAuth = new HttpRequestMessage()
                {
                    Version = new Version(1, 1),
                    RequestUri = requestMessage.RequestUri!,
                    Method = HttpMethod.Get
                };
                _logger.LogInformation("ConfigureHttpRequestMessageAsync: {RequestUri}", requestMessageAuth.RequestUri);
                using var httpMessageInvokerAuth = new HttpMessageInvoker(socketsHttpHandlerAuth);
                using var responseMessage = await httpMessageInvokerAuth.SendAsync(requestMessageAuth, CancellationToken.None);
                responseMessage.EnsureSuccessStatusCode();
                _ = await responseMessage.Content.ReadAsStringAsync();
                _logger.LogInformation("ConfigureHttpRequestMessageAsync: {RequestUri} success", requestMessageAuth.RequestUri);
            }
            catch (Exception error)
            {
                _logger.LogError(error, "ConfigureHttpRequestMessageAsync: {RequestUri} failed", requestMessage.RequestUri);
                throw;
            }
        }
    }
}
