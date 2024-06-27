// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net.WebSockets;

using Yarp.ReverseProxy.Configuration;


using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelWebSocketAuthenticationCertificate
    : ITransportTunnelWebSocketAuthentication
    , IDisposable
{
    private readonly ICertificateConfigLoader _certificateConfigLoader;
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TransportTunnelWebSocketAuthenticationCertificate> _logger;

    private readonly ConcurrentDictionary<string, X509CertificateCollection> _clientCertifiacteCollectionByTunnelId;
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

        _clientCertifiacteCollectionByTunnelId = new ConcurrentDictionary<string, X509CertificateCollection>(StringComparer.OrdinalIgnoreCase);

        _unregisterCertificatePathWatcher = ChangeToken.OnChange(
            _certificatePathWatcher.GetChangeToken,
            () => ReloadCertificate()
            );
    }

    public TransportTunnelWebSocketAuthenticationCertificate()
    {
    }

    public ValueTask<bool> ConfigureClientWebSocketAsync(TunnelConfig config, ClientWebSocket clientWebSocketocket)
    {
        if (!ClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
        {
            return new(false);
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
                                    var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificate(certificateConfig, config.TunnelId, true);
                                    if (certificate is not null)
                                    {
                                        _ = srcClientCertifiacteCollection.Add(certificate);

                                        ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                                        if (certificateConfig.IsFileCert)
                                        {
                                            _certificatePathWatcher.AddWatchUnsynchronized(certificateConfig);
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
                                    var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificate(certificateConfig, keyname, true);
                                    if (certificate is not null)
                                    {
                                        _ = srcClientCertifiacteCollection.Add(certificate);

                                        ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                                        if (certificateConfig.IsFileCert)
                                        {
                                            _certificatePathWatcher.AddWatchUnsynchronized(certificateConfig);
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

                var sslClientCertificates = clientWebSocketocket.Options.ClientCertificates ??= [];
                sslClientCertificates.AddRange(srcClientCertifiacteCollection);
            }

            {
                if (config.Authentication.ClientCertifiacteCollection is { } srcClientCertifiacteCollection)
                {
                    var sslClientCertificates = clientWebSocketocket.Options.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(srcClientCertifiacteCollection);
                }
            }

            return new(true);
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "Failed to load certificate");
            return new(true);
        }
    }

    private void ReloadCertificate()
    {
        var certificateCollections = _clientCertifiacteCollectionByTunnelId.Values.ToList();
        _clientCertifiacteCollectionByTunnelId.Clear();
        _logger.LogInformation("Certifactes cache cleared");
        foreach (var certificateCollection in certificateCollections)
        {
            ClientCertificateLoader.DisposeCertificates(certificateCollection, null);
            certificateCollection.Clear();
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
