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
    , IDisposable
{
    private readonly TransportTunnelAuthenticationCertificateOptions _options;
    private readonly RemoteCertificateValidationUtility _remoteCertificateValidation;
    private readonly IYarpCertificateLoader _certificateConfigLoader;
    private readonly YarpCertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TransportTunnelHttp2AuthenticatorCertificate> _logger;

    private readonly ConcurrentDictionary<string, YarpCertificateCollection> _clientCertifiacteCollectionByTunnelId;
    private IDisposable? _unregisterCertificatePathWatcher;

    public TransportTunnelHttp2AuthenticatorCertificate(
        IOptions<TransportTunnelAuthenticationCertificateOptions> options,
        RemoteCertificateValidationUtility remoteCertificateValidationUtility,
        IYarpCertificateLoader certificateConfigLoader,
        YarpCertificatePathWatcher certificatePathWatcher,
        ILogger<TransportTunnelHttp2AuthenticatorCertificate> logger
        )
    {
        _options = options.Value;
        _remoteCertificateValidation = remoteCertificateValidationUtility;
        _certificateConfigLoader = certificateConfigLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;

        _clientCertifiacteCollectionByTunnelId = new(StringComparer.OrdinalIgnoreCase);
        _unregisterCertificatePathWatcher = ChangeToken.OnChange(
            _certificatePathWatcher.GetChangeToken,
            () => ReloadCertificate()
            );
    }

    public string GetAuthenticationName() => "ClientCertificate";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!YarpClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
        {
            return new(default(HttpMessageInvoker));
        }
        try
        {
            {
                var currentCertifiacteCollection = YarpCertificateCollection.GetCertificateCollection(
                    _clientCertifiacteCollectionByTunnelId,
                    _certificateConfigLoader,
                    _certificatePathWatcher,
                    config.TunnelId,
                    config.Authentication.ClientCertificate,
                    config.Authentication.ClientCertificates,
                    config.Authentication.ClientCertificateCollection,
                    _logger);

                if (currentCertifiacteCollection.TryGet(out var collection, out _, out _)
                    && (0 < collection.Count))
                {
                    var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(collection);
                }
            }

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

    private void ReloadCertificate()
    {
        var certificateCollections = _clientCertifiacteCollectionByTunnelId.Values.ToList();
        if (0 < certificateCollections.Count)
        {
            _clientCertifiacteCollectionByTunnelId.Clear();
            _logger.LogInformation("Certifactes cache cleared");
            foreach (var certificateCollection in certificateCollections)
            {
                certificateCollection.Dirty();
            }
        }
    }

    private void Dispose(bool disposing)
    {
        using (var unregisterCertificatePathWatcher = _unregisterCertificatePathWatcher)
        {
            ReloadCertificate();
            if (disposing)
            {
                _unregisterCertificatePathWatcher = null;
            }
        }
    }

    ~TransportTunnelHttp2AuthenticatorCertificate()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
