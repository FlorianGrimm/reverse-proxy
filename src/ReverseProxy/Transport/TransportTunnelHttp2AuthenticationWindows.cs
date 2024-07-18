// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;
/*
    I toke me a few days to learn that the Windows authentication is not supported over HTTP/2.
    So Websocket is the option for Windows authentication.
    If you live in a VPN-Hell, you may like to use the Windows authentication.
    I saw only few companies that have an own PKI infrastructure so ClientSecret is not for everyone.
    I saw more successfull OAuth2 Applications. But they need internet access.
    A JWT Auth is also expensive - validation. So a cookie auth with JWT may be an option.
    In the same way, the cookie with Windows authentication is an option.

    I saw service user with disabled password.
    And certicates that run out of life - Even big ones that made it into the news..

    Brain fart? Or a good idea?

    GET /_tunnelH2/{clusterId} HTTP/1.1 - Returns the cookie
    POST /_tunnelH2/{clusterId} HTTP/2 - with the given cookie to establish the tunnel connection

    GET /_tunnelJWT/{clusterId} HTTP/* - Returns the cookie
    POST /_tunnelJWT/{clusterId} HTTP/2 - with the given cookie to establish the tunnel connection
 */
internal sealed class TransportTunnelHttp2AuthenticationWindows
    : ITransportTunnelHttp2Authentication
{
    private readonly ConcurrentDictionary<string, PerTunnel> _perTunnel = new(StringComparer.CurrentCultureIgnoreCase);
    private readonly ILogger<TransportTunnelHttp2AuthenticationWindows> _logger;

    public TransportTunnelHttp2AuthenticationWindows(
        ILogger<TransportTunnelHttp2AuthenticationWindows> logger
        )
    {
        _logger = logger;
    }

    public string GetAuthenticationName() => "Windows";

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
        return await GetPerTunnel(tunnel.TunnelId).ConfigureSocketsHttpHandlerAsync(tunnel, socketsHttpHandler);
    }

    public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        var perTunnel = GetPerTunnel(tunnel.TunnelId);
        await perTunnel.ConfigureHttpRequestMessageAsync(tunnel, requestMessage);
    }

    internal sealed class PerTunnel(ILogger logger)
    {
        private readonly ILogger _logger = logger;
        private readonly CookieContainer _cookieContainer = new();
        
        public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
        {
            socketsHttpHandler.Credentials = System.Net.CredentialCache.DefaultCredentials;
            socketsHttpHandler.CookieContainer = _cookieContainer;
            return new(default(HttpMessageInvoker));
        }
        public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
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
                using var httpMessageInvokerAuth = new HttpMessageInvoker(socketsHttpHandlerAuth);
                using var responseMessage = await httpMessageInvokerAuth.SendAsync(requestMessageAuth, CancellationToken.None);
                responseMessage.EnsureSuccessStatusCode();
                var response = await responseMessage.Content.ReadAsStringAsync();
                if (string.Equals(response, "OK"))
                {
                }
                else {
#warning HERE
                    throw new Exception();
                }
                //var cookie = new Cookie()
                //{
                //    Name = "Auth",
                //    Value = auth,
                //    Domain = requestMessage.RequestUri!.Host,
                //    Path = requestMessage.RequestUri!.AbsolutePath,
                //    HttpOnly = true,
                //    Secure = true
                //};
                //_cookieContainer.Add(requestMessage.RequestUri!, cookie);
            }
            catch (Exception error){
                _logger.LogError(error, "TODO");
                throw;
            }
        }
    }
}
