// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Net.Http;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticatorBasic
    : ITransportTunnelWebSocketAuthenticator
{
    private string _password = string.Empty;
    private readonly ILogger<TransportTunnelWebSocketAuthenticatorBasic> _logger;

    public TransportTunnelWebSocketAuthenticatorBasic(
        IOptionsMonitor<TransportTunnelAuthenticationBasicOptions> options,
        ILogger<TransportTunnelWebSocketAuthenticatorBasic> logger
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
            _password = System.Convert.ToBase64String(hash);
        }
        else
        {
            _password = string.Empty;
        }

    }

    public string GetAuthenticationName() => "Basic";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
    {
        if (string.IsNullOrEmpty(_password))
        {
            _logger.LogError("No Password");
        }
        else
        {
            clientWebSocket.Options.Credentials = new NetworkCredential("Tunnel", _password);
        }
        return default;
    }
}
