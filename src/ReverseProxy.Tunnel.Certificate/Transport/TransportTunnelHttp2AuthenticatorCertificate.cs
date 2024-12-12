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
    //private readonly ClientCertificateValidationHttp2 _certificateValidation;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger<TransportTunnelHttp2AuthenticatorCertificate> _logger;

    //private readonly CertificateRequestCollectionDictionary _clientCertificateCollectionByTunnelId;

    public TransportTunnelHttp2AuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        ICertificateManager certificateManager,
        ILogger<TransportTunnelHttp2AuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _certificateManager = certificateManager;
        _logger = logger;
    }

    public string GetAuthenticationName() => Yarp.ReverseProxy.Tunnel.TunnelCertificateConstants.AuthenticationName;

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!Microsoft.AspNetCore.Builder.TransportCertificateExtensions.IsClientCertificate(
            config.TransportAuthentication.Mode))
        {
            return new(default(HttpMessageInvoker));
        }
        if (tunnel.Model.Config.TransportAuthentication.ClientCertificate is { Length: > 0 } clientCertificate)
        {
            try
            {
                using (var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(clientCertificate))
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
#warning TODO                        socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback = _certificateValidation.RemoteCertificateValidationCallback;
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
            }
        }
        return new(default(HttpMessageInvoker));
    }


    public ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
        => ValueTask.CompletedTask;
}
