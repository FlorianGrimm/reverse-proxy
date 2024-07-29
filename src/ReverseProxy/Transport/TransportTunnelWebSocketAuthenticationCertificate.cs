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
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelWebSocketAuthenticationCertificate
    : ITransportTunnelWebSocketAuthentication
    , IDisposable
{
    private readonly ICertificateConfigLoader _certificateConfigLoader;
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TransportTunnelWebSocketAuthenticationCertificate> _logger;

    private readonly ConcurrentDictionary<string, X509CertificateCollection> _clientCertifiacteCollectionByTunnelId;
    private readonly HashSet<CertificateConfig> _allCertificateConfig;
    private IDisposable? _unregisterCertificatePathWatcher;

    public TransportTunnelWebSocketAuthenticationCertificate(
                ICertificateConfigLoader certificateConfigLoader,
        CertificatePathWatcher certificatePathWatcher,
        ILogger<TransportTunnelWebSocketAuthenticationCertificate> logger
        )
    {
        _certificateConfigLoader = certificateConfigLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;

        _clientCertifiacteCollectionByTunnelId = new(StringComparer.OrdinalIgnoreCase);
        _allCertificateConfig = new();
        _unregisterCertificatePathWatcher = ChangeToken.OnChange(
            _certificatePathWatcher.GetChangeToken,
            () => ReloadCertificate()
            );
    }

    public string GetAuthenticationName() => "ClientCertificate";

    public void ConfigureWebSocketConnectionOptions(TransportTunnelConfig config, HttpConnectionOptions options)
    {
    }

    public ValueTask<HttpMessageInvoker?> ConfigureClientWebSocket(TransportTunnelConfig config, ClientWebSocket clientWebSocket)
    {
        if (!ClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
        {
            _logger.LogWarning("ClientCertificate authentication mode expected");
            return ValueTask.FromResult<HttpMessageInvoker?>(default);
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

                                        if (certificateConfig.IsFileCert)
                                        {
                                            lock (_allCertificateConfig)
                                            {
                                                if (_allCertificateConfig.Add(certificateConfig))
                                                {
                                                    _certificatePathWatcher.AddWatch(certificateConfig);
                                                }
                                            }
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

                                        if (certificateConfig.IsFileCert)
                                        {
                                            lock (_allCertificateConfig)
                                            {
                                                if (_allCertificateConfig.Add(certificateConfig))
                                                {
                                                    _certificatePathWatcher.AddWatch(certificateConfig);
                                                }
                                            }
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
                                _logger.LogTrace("Certifactes loaded {TunnelId}", config.TunnelId);
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

                if (srcClientCertifiacteCollection is { Count: > 0 }) {
                    _logger.LogTrace("Certifactes added by config {TunnelId}", config.TunnelId);
                    var sslClientCertificates = clientWebSocket.Options.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(srcClientCertifiacteCollection);
                }
            }

            {
                if (config.Authentication.ClientCertifiacteCollection is { Count:>0 } srcClientCertifiacteCollection)
                {
                    _logger.LogTrace("Certifactes added by config collection {TunnelId}", config.TunnelId);
                    var sslClientCertificates = clientWebSocket.Options.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(srcClientCertifiacteCollection);
                }
            }

            clientWebSocket.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => OnRemoteCertificateValidation(sender, certificate, chain, sslPolicyErrors, clientWebSocket.Options);
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed to load certificate");
        }

        return ValueTask.FromResult<HttpMessageInvoker?>(default);
    }

#pragma warning disable IDE0060 // Remove unused parameter
    private bool OnRemoteCertificateValidation(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors, ClientWebSocketOptions options)
#pragma warning restore IDE0060 // Remove unused parameter
    {
        if (certificate is null)
        {
            // TODO: no idea
            _logger.LogWarning("RemoteCertificateValidation: No certificate");
            return false;
        }
        var certHash = certificate.GetCertHash();
        foreach (var clientCertificate in options.ClientCertificates)
        {
            if (certHash.SequenceEqual(clientCertificate.GetCertHash()))
            {
                _logger.LogInformation("RemoteCertificateValidation: Certificate found");
                return true;
            }
        }
        _logger.LogInformation("RemoteCertificateValidation: Certificate no match");
        return false;
    }

    private void ReloadCertificate()
    {
        List<X509CertificateCollection> certificateCollections;
        List<CertificateConfig> allCertificateConfig;
        lock (_allCertificateConfig)
        {
            certificateCollections = _clientCertifiacteCollectionByTunnelId.Values.ToList();
            allCertificateConfig = _allCertificateConfig.ToList();

            if (0 == certificateCollections.Count
                && 0 == allCertificateConfig.Count)
            {
                return;
            }

            _clientCertifiacteCollectionByTunnelId.Clear();
            _allCertificateConfig.Clear();

            foreach (var certificateConfig in _allCertificateConfig)
            {
                _certificatePathWatcher.RemoveWatch(certificateConfig);
            }
            foreach (var certificateCollection in certificateCollections)
            {
                ClientCertificateLoader.DisposeCertificates(certificateCollection, null);
                certificateCollection.Clear();
            }
        }
        _logger.LogInformation("Certifactes cache cleared");
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

    ~TransportTunnelWebSocketAuthenticationCertificate()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
