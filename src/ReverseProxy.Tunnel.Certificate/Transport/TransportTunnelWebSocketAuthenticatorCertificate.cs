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
    private readonly IYarpCertificateCollectionFactory _certificateCollectionFactory;
    private readonly ILogger<TransportTunnelWebSocketAuthenticatorCertificate> _logger;

    private readonly ConcurrentDictionary<string, YarpCertificateCollection> _clientCertifiacteCollectionByTunnelId;
    private readonly HashSet<CertificateConfig> _allCertificateConfig;

    public TransportTunnelWebSocketAuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        RemoteCertificateValidationUtility remoteCertificateValidationUtility,
        IYarpCertificateCollectionFactory certificateCollectionFactory,
        ILogger<TransportTunnelWebSocketAuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _remoteCertificateValidation = remoteCertificateValidationUtility;
        _certificateCollectionFactory = certificateCollectionFactory;
        _logger = logger;

        _clientCertifiacteCollectionByTunnelId = new(StringComparer.OrdinalIgnoreCase);
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
            {
                var currentCertifiacteCollection = YarpCertificateCollection.GetCertificateCollection(
                    _clientCertifiacteCollectionByTunnelId,
                    _certificateCollectionFactory,
                    config.TunnelId,
                    true,
                    config.Authentication.ClientCertificate,
                    config.Authentication.ClientCertificates,
                    config.Authentication.ClientCertificateCollection,
                    _logger);

                if (currentCertifiacteCollection.GiveAway() is { Count: > 0 } collection) {
                    _logger.LogTrace("Certifactes added by config {TunnelId}", config.TunnelId);
                    var sslClientCertificates = clientWebSocket.Options.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(collection);
                }
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
