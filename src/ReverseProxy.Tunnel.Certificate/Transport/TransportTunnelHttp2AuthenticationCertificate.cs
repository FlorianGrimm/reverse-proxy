// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelHttp2AuthenticationCertificate
    : ITransportTunnelHttp2Authentication
    , IDisposable
{
    private readonly ICertificateConfigLoader _certificateConfigLoader;
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TransportTunnelHttp2AuthenticationCertificate> _logger;

    private readonly ConcurrentDictionary<string, X509CertificateCollection> _clientCertifiacteCollectionByTunnelId;
    private IDisposable? _unregisterCertificatePathWatcher;

    public TransportTunnelHttp2AuthenticationCertificate(
        ICertificateConfigLoader certificateConfigLoader,
        CertificatePathWatcher certificatePathWatcher,
        ILogger<TransportTunnelHttp2AuthenticationCertificate> logger
        )
    {
        _certificateConfigLoader = certificateConfigLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;

        _clientCertifiacteCollectionByTunnelId = new ConcurrentDictionary<string, X509CertificateCollection>(StringComparer.OrdinalIgnoreCase);

        _unregisterCertificatePathWatcher = ChangeToken.OnChange(
            _certificatePathWatcher.GetChangeToken,
            () => ReloadCertificate()
            );
    }

    public string GetAuthenticationName() => "ClientCertificate";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!ClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
        {
            return new(default(HttpMessageInvoker));
        }

        try
        {
            {
                X509CertificateCollection? srcClientCertifiacteCollection = null;
                while (srcClientCertifiacteCollection is null)
                {
                    if (_clientCertifiacteCollectionByTunnelId.TryGetValue(config.TunnelId, out srcClientCertifiacteCollection))
                    {
                        break;
                    }

                    lock (this)
                    {
                        if (_clientCertifiacteCollectionByTunnelId.TryGetValue(config.TunnelId, out srcClientCertifiacteCollection))
                        {
                            break;
                        }
                        else
                        {
                            srcClientCertifiacteCollection = [];
                            {
                                if (config.Authentication.ClientCertificate is { } certificateConfig)
                                {
                                    var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateWithPrivateKey(certificateConfig, config.TunnelId);
                                    if (certificate is not null)
                                    {
                                        _ = srcClientCertifiacteCollection.Add(certificate);

                                        ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                                        if (certificateConfig.IsFileCert())
                                        {
                                            _certificatePathWatcher.AddWatch(certificateConfig);
                                        }
                                    }
                                    else
                                    {
                                        ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
                                    }
                                }
                            }
                            if (config.Authentication.ClientCertificates is { Count: > 0 } authenticationClientCertificates)
                            {
                                for (var index = 0; index < authenticationClientCertificates.Count; index++)
                                {
                                    var certificateConfig = authenticationClientCertificates[index];
                                    var keyname = $"{config.TunnelId}-{index}";
                                    var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateWithPrivateKey(certificateConfig, keyname);
                                    if (certificate is not null)
                                    {
                                        _ = srcClientCertifiacteCollection.Add(certificate);

                                        ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                                        if (certificateConfig.IsFileCert())
                                        {
                                            _certificatePathWatcher.AddWatch(certificateConfig);
                                        }
                                        else
                                        {
                                            ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
                                        }
                                    }
                                }
                            }
                            if (_clientCertifiacteCollectionByTunnelId.TryAdd(config.TunnelId, srcClientCertifiacteCollection))
                            {
                                _logger.LogInformation("Certifactes loaded");
                            }
                            else
                            {
                                // could not be added - so dispose it 
                                ClientCertificateLoader.DisposeCertificates(srcClientCertifiacteCollection, null);

                                // and try again
                                srcClientCertifiacteCollection = null;
                            }
                        }
                    }
                }
                var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= [];
                sslClientCertificates.AddRange(srcClientCertifiacteCollection);
            }

            {
                if (config.Authentication.ClientCertificateCollection is { } srcClientCertifiacteCollection)
                {
                    var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(srcClientCertifiacteCollection);
                }
            }
            if (socketsHttpHandler.SslOptions.ClientCertificates is { Count: > 0 } clientCertificates)
            {
                socketsHttpHandler.SslOptions.TargetHost = config.Url;
                socketsHttpHandler.SslOptions.CertificateRevocationCheckMode = X509RevocationMode.NoCheck;
                if (socketsHttpHandler.SslOptions.EnabledSslProtocols == System.Security.Authentication.SslProtocols.None)
                {
                    socketsHttpHandler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13;
                }
                socketsHttpHandler.SslOptions.LocalCertificateSelectionCallback = (sender, host, localCertificates, remoteCertificate, acceptableIssuers) =>
                {
                    return clientCertificates[0];
                };
                socketsHttpHandler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, error) =>
                {
                    _logger.LogInformation("RemoteCertificateValidation: {issuer} {error}", certificate?.Issuer, error);
                    return true;
                };
            }

            //
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
                ClientCertificateLoader.DisposeCertificates(certificateCollection, null);
                certificateCollection.Clear();
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

    ~TransportTunnelHttp2AuthenticationCertificate()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
