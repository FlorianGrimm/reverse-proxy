// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Transport;

public sealed class TransportTunnelHttp2AuthenticationCertificate
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


    public ValueTask<bool> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
    {
        var config = tunnel.Model.Config;
        if (!ClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
        {
            return new(false);
        }

#warning HELP pretty please I have no experiences with clientcertificates

        try
        {
            {
                // TODO: bad until it works
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

            // for in Memory Configuration
            {
                if (config.Authentication.ClientCertifiacteCollection is { } srcClientCertifiacteCollection)
                {
                    var sslClientCertificates = socketsHttpHandler.SslOptions.ClientCertificates ??= [];
                    sslClientCertificates.AddRange(srcClientCertifiacteCollection);
                }
            }

            //
            return new(true);
        }
        catch (System.Exception error)
        {
            _logger.LogError(error, "TransportTunnelHttp2AuthenticationCertificate");
            return new(true);
        }
    }

    public ValueTask<bool> ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        return new(false);
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

    ~TransportTunnelHttp2AuthenticationCertificate()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}

public sealed class KeyOfCertificateConfigEqualityComparer : IEqualityComparer<KeyOfCertificateConfig>
{
    private static KeyOfCertificateConfigEqualityComparer? _comparer;
    public static KeyOfCertificateConfigEqualityComparer Comparer => _comparer ??= new();

    public bool Equals(KeyOfCertificateConfig? x, KeyOfCertificateConfig? y)
    {
        if (ReferenceEquals(x, y)) { return true; }
        if (x is null || y is null) { return false; }
        return x.Equals(y);
    }

    public int GetHashCode([DisallowNull] KeyOfCertificateConfig obj) => obj.GetHashCode();
}

public sealed class KeyOfCertificateConfig(List<CertificateConfig> list)
    : IEquatable<KeyOfCertificateConfig>
{
    private readonly CertificateConfig[] _items = [.. list];

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is KeyOfCertificateConfig other && Equals(other);

    /// <inheritdoc/>
    public bool Equals(KeyOfCertificateConfig? other)
    {
        if (other is null) { return false; }

        if (_items.Length != other._items.Length) { return false; }
        for (var idx = 0; idx < _items.Length; idx++)
        {
            if (!_items[idx].Equals(other._items[idx])) { return false; }
        }
        return true;
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode result = new();
        for (var idx = 0; idx < _items.Length; idx++)
        {
            result.Add(_items[idx]);
        }
        return result.ToHashCode();
    }
}
