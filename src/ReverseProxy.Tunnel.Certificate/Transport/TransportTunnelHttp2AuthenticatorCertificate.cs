// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
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
    private readonly ClientCertificateValidationHttp2 _certificateValidation;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger<TransportTunnelHttp2AuthenticatorCertificate> _logger;

    private readonly CertificateRequestCollectionDictionary _clientCertificateCollectionByTunnelId;

    public TransportTunnelHttp2AuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        ICertificateManager certificateManager,
        ILogger<TransportTunnelHttp2AuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _certificateValidation = new ClientCertificateValidationHttp2(
            new ClientCertificateValidationHttp2Options()
            {
                CustomValidation = _options.CustomValidation,
                IgnoreSslPolicyErrors = _options.IgnoreSslPolicyErrors
            },
            logger);
        _certificateManager = certificateManager;
        _logger = logger;

        _clientCertificateCollectionByTunnelId = new CertificateRequestCollectionDictionary(
            certificateManager,
            nameof(TransportTunnelHttp2AuthenticatorCertificate),
            _options.CertificateRequirement,
            adjustRequirement);
    }

    private static CertificateRequirement adjustRequirement(CertificateRequirement requirement)
        => requirement with { ClientCertificate = true };

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
            var certificateRequestCollection = _clientCertificateCollectionByTunnelId.GetOrAddConfiguration(
                config.ToParameter());
            using (var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(certificateRequestCollection))
            {
                var currentCertificateCollection = shareCurrentCertificateCollection.GiveAway();

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
                    socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback = _certificateValidation.RemoteCertificateValidationCallback;
                }
                else
                {
                    throw new InvalidOperationException("No client certificate found");
                }
                return new(new HttpMessageInvoker(socketsHttpHandler, true));
            }
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
