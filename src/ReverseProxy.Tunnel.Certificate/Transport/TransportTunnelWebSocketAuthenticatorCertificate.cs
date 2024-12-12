// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Connections.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticatorCertificate
    : ITransportTunnelWebSocketAuthenticator
{
    private readonly TransportTunnelAuthenticationCertificateOptions _options;
    //private readonly ClientCertificateValidationWebSocket _clientCertificateValidation;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger<TransportTunnelWebSocketAuthenticatorCertificate> _logger;

    public TransportTunnelWebSocketAuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        ICertificateManager certificateManager,
        ILogger<TransportTunnelWebSocketAuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _certificateManager = certificateManager;
        _logger = logger;
    }


    public string GetAuthenticationName() => "ClientCertificate";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
    {
        if (config.TransportAuthentication.ClientCertificate is { Length: > 0 } clientCertificate)
        {
            try
            {
                using var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(clientCertificate);
                var currentCertificateCollection = shareCurrentCertificateCollection.GiveAway();

                if (currentCertificateCollection is { Count: > 0 } collection)
                {
                    _logger.LogTrace("Certificates added by config {TunnelId}", config.TunnelId);
                    var sslClientCertificates = clientWebSocket.Options.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(collection);
                }

#warning TODO                clientWebSocket.Options.RemoteCertificateValidationCallback = _clientCertificateValidation.RemoteCertificateValidationCallback;
                if (_options.ConfigureClientWebSocketOptions is { } configureClientWebSocketOptions)
                {
                    configureClientWebSocketOptions(clientWebSocket.Options);
                }
                if (!(clientWebSocket.Options.ClientCertificates is { Count: > 0 }))
                {
                    throw new InvalidOperationException("No client certificate found");
                }
            }
            catch (System.Exception error)
            {
                _logger.LogError(error, "Failed to load certificate");
            }
        }
        return ValueTask.FromResult<HttpMessageInvoker?>(default);
    }
}
