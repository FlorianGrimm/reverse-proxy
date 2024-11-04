// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelHttp2AuthenticatorCertificate
    : ITransportTunnelHttp2Authenticator
{
    private readonly TransportTunnelAuthenticationCertificateOptions _options;
    private readonly RemoteCertificateValidationUtility _remoteCertificateValidation;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger<TransportTunnelHttp2AuthenticatorCertificate> _logger;

    private readonly ConcurrentDictionary<string, CertificateRequestCollection> _clientCertifiacteCollectionByTunnelId = new(StringComparer.OrdinalIgnoreCase);

    public TransportTunnelHttp2AuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        RemoteCertificateValidationUtility remoteCertificateValidationUtility,
        ICertificateManager certificateManager,
        ILogger<TransportTunnelHttp2AuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _remoteCertificateValidation = remoteCertificateValidationUtility;
        _certificateManager = certificateManager;
        _logger = logger;
    }

    public string GetAuthenticationName() => "ClientCertificate";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!Microsoft.AspNetCore.Builder.TransportCertificateExtensions.IsClientCertificate(
            config.Authentication.Mode))
        {
            return new(default(HttpMessageInvoker));
        }
        try
        {

            if (_clientCertifiacteCollectionByTunnelId.TryGetValue(config.TunnelId, out var certificateRequestCollection))
            {
                // OK
            }
            else
            {
                certificateRequestCollection = _certificateManager.TryAddConfiguration(
                    _clientCertifiacteCollectionByTunnelId,
                    config.TunnelId,
                    () => {
                        var todoThatComesFromTheConfiguration = new CertificateRequirement();
                        var finallyCertificateRequirement = todoThatComesFromTheConfiguration with
                        {
                            ClientCertificate = true
                        };
                        var result = _certificateManager.AddConfiguration(
                            $"TunnelClientCertificate/{config.TunnelId}",
                            config.Authentication.ClientCertificate,
                            config.Authentication.ClientCertificates,
                            config.Authentication.ClientCertificateCollection,
                            finallyCertificateRequirement
                            );
                        return result;
                    }
                    );
            }
            if (_clientCertifiacteCollectionByTunnelId.TryGetValue(config.TunnelId, out var certificateRequestCollection))
            {
                // OK
            }
            else
            {
                lock (_clientCertifiacteCollectionByTunnelId)
                {
                    if (_clientCertifiacteCollectionByTunnelId.TryGetValue(config.TunnelId, out certificateRequestCollection))
                    {
                        //OK
                    }
                    else
                    {
                        var todoThatComesFromTheConfiguration = new CertificateRequirement();
                        var finallyCertificateRequirement = todoThatComesFromTheConfiguration with
                        {
                            ClientCertificate = true
                        };
                        certificateRequestCollection = _certificateManager.AddConfiguration(
                            $"TunnelClientCertificate/{config.TunnelId}",
                            config.Authentication.ClientCertificate,
                            config.Authentication.ClientCertificates,
                            config.Authentication.ClientCertificateCollection,
                            finallyCertificateRequirement
                            );
                        _certificateManager.AddRequestCollection(certificateRequestCollection);
                    }
                }
            }
            var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(certificateRequestCollection);
            var currentCertificateCollection = shareCurrentCertificateCollection.Value;
            // shareCurrentCertificateCollection.Dispose is not called because the collection (certificates) are given away

            if (currentCertificateCollection is { Count: > 0 } collection)
            {
                var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= [];
                sslClientCertificates.AddRange(collection);
            }
            // else hopefully ConfigureSslOptions will be called to add the certificate

            socketsHttpHandler.SslOptions.TargetHost = config.Url;
            if (_options.ConfigureSslOptions is { } configureSslOptions)
            {
                configureSslOptions(socketsHttpHandler.SslOptions);
            }
            if (socketsHttpHandler.SslOptions.ClientCertificates is { Count: > 0 } clientCertificates)
            {
                if (socketsHttpHandler.SslOptions.EnabledSslProtocols == System.Security.Authentication.SslProtocols.None)
                {
                    socketsHttpHandler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13;
                }
                socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback = _remoteCertificateValidation.RemoteCertificateValidationCallback;
            }

            return new(new HttpMessageInvoker(socketsHttpHandler, true));
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "TransportTunnelHttp2AuthenticationCertificate");
            return new(default(HttpMessageInvoker));
        }
    }

    public ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
        => ValueTask.CompletedTask;
}
