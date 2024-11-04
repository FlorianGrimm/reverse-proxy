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
    private readonly RemoteCertificateValidationUtility _remoteCertificateValidation;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger<TransportTunnelWebSocketAuthenticatorCertificate> _logger;

    private readonly CertificateRequestCollectionDictionary _clientCertificateCollectionByTunnelId;

    private readonly HashSet<CertificateConfig> _allCertificateConfig;

    public TransportTunnelWebSocketAuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        RemoteCertificateValidationUtility remoteCertificateValidationUtility,
        ICertificateManager certificateManager,
        ILogger<TransportTunnelWebSocketAuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _remoteCertificateValidation = remoteCertificateValidationUtility;
        _certificateManager = certificateManager;
        _logger = logger;

#warning TODO
        var certificateRequirement = new CertificateRequirement()
        {
            ClientCertificate = true
        };
        _clientCertificateCollectionByTunnelId = new CertificateRequestCollectionDictionary(certificateManager, nameof(TransportTunnelWebSocketAuthenticatorCertificate), certificateRequirement);
        _allCertificateConfig = new();
    }

    public string GetAuthenticationName() => "ClientCertificate";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
    {
        try
        {
            var certificateRequestCollection = _clientCertificateCollectionByTunnelId.GetOrAddConfiguration(
                config.TunnelId,
                config.Authentication.ClientCertificate,
                config.Authentication.ClientCertificates,
                config.Authentication.ClientCertificateCollection);
            using var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(certificateRequestCollection);
            var currentCertificateCollection = shareCurrentCertificateCollection.GiveAway();

            if (currentCertificateCollection is { Count: > 0 } collection)
            {
                _logger.LogTrace("Certificates added by config {TunnelId}", config.TunnelId);
                var sslClientCertificates = clientWebSocket.Options.ClientCertificates ??= [];
                sslClientCertificates.AddRange(collection);
            }

            clientWebSocket.Options.RemoteCertificateValidationCallback = _remoteCertificateValidation.RemoteCertificateValidationCallback;
            if (_options.ConfigureClientWebSocketOptions is { } configureClientWebSocketOptions)
            {
                configureClientWebSocketOptions(clientWebSocket.Options);
            }
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed to load certificate");
        }

        return ValueTask.FromResult<HttpMessageInvoker?>(default);
    } 
}
