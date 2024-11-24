// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelHttp2AuthenticatorBasic
    : ITransportTunnelHttp2Authenticator
{
    private string _password = string.Empty;
    private readonly ILogger<TransportTunnelHttp2AuthenticatorBasic> _logger;

    public TransportTunnelHttp2AuthenticatorBasic(
        IOptionsMonitor<TransportTunnelAuthenticationBasicOptions> options,
        ILogger<TransportTunnelHttp2AuthenticatorBasic> logger
        )
    {
        _logger = logger;
        options.OnChange(OptionsOnChange);
        OptionsOnChange(options.CurrentValue, default);
    }

    private void OptionsOnChange(TransportTunnelAuthenticationBasicOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }
        if (options.Password is { Length: > 0 } plainPassword)
        {
            var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(plainPassword));
            var password = System.Convert.ToBase64String(hash);

            _password = $"Tunnel:{password}";
        }
        else
        {
            _password = string.Empty;
        }

    }

    public string GetAuthenticationName() => "Basic";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
        => new(default(HttpMessageInvoker));

    public ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        if (string.IsNullOrEmpty(_password))
        {
            _logger.LogError("No Password");
        }
        else
        {
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", _password);
        }
        return default;
    }
}
