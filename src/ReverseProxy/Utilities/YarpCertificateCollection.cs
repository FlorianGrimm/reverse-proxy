#nullable enable

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;

using static Yarp.ReverseProxy.Utilities.YarpCertificateCollection.State;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Abstracts the loading/house-keeping of certificates.
/// </summary>
public sealed partial class YarpCertificateCollection
    : IDisposable
{
    private readonly IYarpCertificateLoader _certificateLoader;
    private readonly IYarpCertificatePathWatcher? _certificatePathWatcher;
    private readonly string _id;
    private readonly bool _loadWithPrivateKey;
    private readonly TimeProvider _timeProvider;
    private LoadParameter? _currentParameter;
    private State? _currentState;

    /// <summary>
    /// Guess what a constructor does.
    /// </summary>
    /// <param name="certificateLoader">The certificate loader</param>
    /// <param name="certificatePathWatcher">The filewatche</param>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="loadWithPrivateKey">load with private key - or without if false.</param>
    /// <param name="timeProvider">The TimeProvider</param>
    public YarpCertificateCollection(
        IYarpCertificateLoader certificateLoader,
        IYarpCertificatePathWatcher? certificatePathWatcher,
        string id,
        bool loadWithPrivateKey,
        TimeProvider timeProvider
        )
    {
        _certificateLoader = certificateLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _id = id;
        _loadWithPrivateKey = loadWithPrivateKey;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Give away the certificate collection - assume you cannot give it back.
    /// </summary>
    /// <returns></returns>
    public X509CertificateCollection? GiveAway()
    {
        if (_currentState is { } currentState
            && currentState.Collection is { } result)
        {
            currentState.DisposeCertificates = false;
            return result;
        }
        else
        {
            return default;
        }
    }

    public Shared<X509CertificateCollection>? ShareCertificateCollection()
    {
        if (_currentState is { } currentState
            && currentState.Collection is { } result)
        {
            currentState.ReferenceCounter++;

            return new Shared<X509CertificateCollection>(
                result,
                (value, _) => { GiveBack(value); });

            void GiveBack(X509CertificateCollection? value)
            {
                if (value is { }
                    && _currentState is { } state
                    && state.Collection is { } collection
                    && ReferenceEquals(value, collection)
                    )
                {
                    state.ReferenceCounter--;
                }
            }
        }
        else
        {
            return null;
        }

    }

    public X509Certificate? GiveAwayCertificate()
    {
        if (_currentState is { Collection: { Count: > 0 } collection })
        {
            if (0 <= _currentState.Valid)
            {
                _currentState.DisposeCertificates = false;
                return collection[_currentState.Valid];
            }
            else
            {
                // REVIEW: is this possible?
                _currentState.DisposeCertificates = false;
                return collection[0];
            }
        }
        return null;
    }

    public Shared<X509Certificate>? ShareCertificate()
    {
        if (_currentState is { Collection: { Count: > 0 } collection })
        {
            if (0 <= _currentState.Valid)
            {
                return new Shared<X509Certificate>(
                    collection[_currentState.Valid],
                    (value, _) => { GiveBack(collection); });
            }
            else
            {
                // REVIEW: is this possible?
                return new Shared<X509Certificate>(
                    collection[0],
                    (value, _) => { GiveBack(collection); });
            }

            void GiveBack(X509CertificateCollection? value)
            {
                if (value is { }
                    && _currentState is { } state
                    && state.Collection is { } collection
                    && ReferenceEquals(value, collection)
                    )
                {
                    state.ReferenceCounter--;
                }
            }
        }
        return null;
    }

    internal bool TryGet(
        [MaybeNullWhen(false)] out X509CertificateCollection collection,
        [MaybeNullWhen(false)] out DateTime notBefore,
        [MaybeNullWhen(false)] out DateTime notAfter
        )
    {
        if (_currentState is { } state
            && state.Collection is { } stateCollection
            )
        {
            collection = stateCollection;
            notBefore = state.NotBefore;
            notAfter = state.NotAfter;
            return true;
        }
        else
        {
            collection = default;
            notBefore = default;
            notAfter = default;
            return false;
        }
    }

    /// <summary>
    /// Loads the certificate collection based on the provided certificate configuration and/or list of certificate configurations.
    /// </summary>
    /// <param name="CertificateConfig">Optional a configuration</param>
    /// <param name="ListCertificateConfig">Optional a list of configuration</param>
    /// <param name="X509CertificateCollection">Optional a list of certificates.</param>
    /// <returns>Fluent this.</returns>
    public YarpCertificateCollection Load(
        CertificateConfig? CertificateConfig,
        List<CertificateConfig>? ListCertificateConfig,
        X509CertificateCollection? X509CertificateCollection
        ) => Load(new LoadParameter(CertificateConfig, ListCertificateConfig, X509CertificateCollection));

    /// <summary>
    /// Loads the certificate collection based on the provided certificate configuration and/or list of certificate configurations.
    /// </summary>
    /// <param name="parameter">The certificate configurations.</param>
    /// <returns>Fluent this.</returns>
    internal YarpCertificateCollection Load(
        LoadParameter parameter
        )
    {
        {
            // fast path if not changed
            var refresh = (_currentState is null) || NeedsReload(parameter);
            if (!refresh) { return this; }
        }
        {
            var previousState = _currentState;
            lock (this)
            {
                {
                    // test again after lock
                    var refresh = (_currentState is null) || NeedsReload(parameter);
                    if (!refresh) { return this; }
                }
                {
                    var state = new State(this);
                    var utcNow = _timeProvider.GetUtcNow();
                    {
                        if (parameter.CertificateConfig is { } certificateConfigItem)
                        {
                            state.Load(certificateConfigItem, _id, utcNow);
                        }
                    }

                    if (parameter.ListCertificateConfig is { Count: > 0 } authenticationClientCertificates)
                    {
                        for (var index = 0; index < authenticationClientCertificates.Count; index++)
                        {
                            if (authenticationClientCertificates[index] is { } certificateConfigItem)
                            {
                                var keyname = $"{_id}-{index}";
                                state.Load(certificateConfigItem, keyname, utcNow);
                            }
                        }
                    }
                    if (parameter.X509CertificateCollection is { } x509CertificateCollection)
                    {
                        state.AddShared(x509CertificateCollection, utcNow);
                    }
                    _currentParameter = parameter;
                    _currentState = state;
                }
            }

            // TODO: Can we dispose this? .. how do we know it's safe to dispose? not in use...
            previousState?.Dispose();

            return this;
        }
    }

    /// <summary>
    /// Check if the certificates needs to be reloaded.
    /// </summary>
    /// <param name="certificateConfig">configuration for loading the certificates.</param>
    /// <param name="listCertificateConfig">configuration for loading the certificates.</param>
    /// <param name="x509CertificateCollection">predefined certificates</param>
    /// <returns>true - reload; false - no need to reload</returns>
    public bool NeedsReload(
        CertificateConfig? certificateConfig,
        List<CertificateConfig>? listCertificateConfig,
        X509CertificateCollection? x509CertificateCollection)
    {
        return NeedsReload(new LoadParameter(certificateConfig, listCertificateConfig, x509CertificateCollection));
    }

    /// <summary>
    /// Check if the certificates needs to be reloaded.
    /// </summary>
    /// <param name="nextLoadParameter">the next request</param>
    /// <returns>true - reload; false - no need to reload</returns>
    public bool NeedsReload(LoadParameter nextLoadParameter)
    {
        if (!(_currentParameter is { } currentCertificateCollectionRequest)
            || _currentState is null)
        {
            return true;
        }

        if (_currentState.CertificateChangeToken is { } changeToken
            && changeToken.HasChanged)
        {
            return true;
        }

        if (!AreEqualCertificateConfig(currentCertificateCollectionRequest.CertificateConfig, nextLoadParameter.CertificateConfig))
        {
            return true;
        }

        return !AreEqualListCertificateConfig(currentCertificateCollectionRequest.ListCertificateConfig, nextLoadParameter.ListCertificateConfig);
    }

    private bool AreEqualListCertificateConfig(List<CertificateConfig>? a, List<CertificateConfig>? b)
    {
        if (ReferenceEquals(a, b)) { return true; }
        if (a is null || b is null) { return false; }
        if (a.Count != b.Count) { return false; }
        for (var index = 0; index < a.Count; index++)
        {
            if (!a[index].Equals(b[index])) { return false; }
        }
        return true;
    }

    private static bool AreEqualCertificateConfig(CertificateConfig? a, CertificateConfig? b)
    {
        if (ReferenceEquals(a, b)) { return true; }
        if (a is null || b is null) { return false; }
        return a.Equals(b);
    }

   

    public void Dispose()
    {
        // TODO: Is it ok to Dispose them - they might be in use
        using (_currentState)
        {
            _currentState = null;
        }
    }

    public void Dirty()
    {
        // TODO: Is it ok to Dispose them - they might be in use
        using (_currentState)
        {
            _currentState = null;
        }
    }

}

// utliity part
public partial class YarpCertificateCollection
{
    /// <summary>
    /// The parameter to load the certificates.
    /// </summary>
    /// <param name="CertificateConfig">configuration for loading the certificates.</param>
    /// <param name="ListCertificateConfig">configuration for loading the certificates.</param>
    /// <param name="X509CertificateCollection">predefined certificates</param>
    public record struct LoadParameter(
        CertificateConfig? CertificateConfig,
        List<CertificateConfig>? ListCertificateConfig,
        X509CertificateCollection? X509CertificateCollection);

    internal sealed class State(
        YarpCertificateCollection yarpCertificateCollection
        ) : IDisposable
    {
        private readonly YarpCertificateCollection _yarpCertificateCollection = yarpCertificateCollection;

        private X509CertificateCollection? _collectionToDispose;

        public IChangeToken? CertificateChangeToken { get; private set; }
        public X509CertificateCollection? Collection { get; private set; }

        // TODO: Test if we can automagic use the valid certifcate (within the date range)
        public DateTime NotBefore = DateTime.MaxValue;
        public DateTime NotAfter = DateTime.MinValue;

        public int ReferenceCounter = 0;
        public bool DisposeCertificates = true;
        public int Valid = -1;

        /// <summary>
        /// Load the certificates defined by the config
        /// </summary>
        /// <param name="certificateConfig">the configuration that specifies the certificates to load.</param>
        /// <param name="keyname"></param>
        /// <param name="utcNow"></param>
        public void Load(
            CertificateConfig certificateConfig,
            string keyname,
            DateTimeOffset utcNow)
        {
            if (_yarpCertificateCollection._loadWithPrivateKey)
            {
                var (certificate, certificateCollection) = _yarpCertificateCollection._certificateLoader.LoadCertificateWithPrivateKey(certificateConfig, keyname);
                PostLoad(certificateConfig, certificate, certificateCollection, utcNow);
            }
            else
            {
                var (certificate, certificateCollection) = _yarpCertificateCollection._certificateLoader.LoadCertificateNoPrivateKey(certificateConfig, keyname);
                PostLoad(certificateConfig, certificate, certificateCollection, utcNow);
            }
        }

        private void PostLoad(
            CertificateConfig certificateConfig,
            X509Certificate2? certificate,
            X509Certificate2Collection? clientCertificateCollection,
            DateTimeOffset utcNow
            )
        {
            if (certificate is not null)
            {
                if (Collection is null)
                {
                    _collectionToDispose = Collection = new X509CertificateCollection();
                }

                AddCertificateIfValid(Collection, certificate, utcNow);

                YarpClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                if (certificateConfig.IsFileCert())
                {
                    if (_yarpCertificateCollection._certificatePathWatcher is { } certificatePathWatcher)
                    {
                        certificatePathWatcher.AddWatch(certificateConfig);
                        if (CertificateChangeToken is null)
                        {
                            CertificateChangeToken = certificatePathWatcher.GetChangeToken();
                        }
                    }
                }
            }
            else
            {
                YarpClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
            }
        }

        internal void AddShared(X509CertificateCollection x509CertificateCollection, DateTimeOffset utcNow)
        {
            var nextCollection = new X509CertificateCollection();
            if (Collection is { } collection)
            {
                foreach (var certificate in nextCollection)
                {
                    nextCollection.Add(certificate);
                }
            }

            foreach (var certificate in x509CertificateCollection)
            {
                AddCertificateIfValid(nextCollection, certificate, utcNow);
            }

            Collection = nextCollection;
        }

        private void AddCertificateIfValid(
            X509CertificateCollection nextCollection,
            X509Certificate certificate,
            DateTimeOffset utcNow)
        {
            if (certificate is not X509Certificate2 certificate2)
            {
                throw new InvalidOperationException("Only X509Certificate2 is supported");
            }

            if (certificate2.NotBefore <= utcNow && utcNow < certificate2.NotAfter)
            {
                // valid
                if (Valid < 0)
                {
                    Valid = nextCollection.Count;
                }
                nextCollection.Add(certificate);
                if (certificate2.NotBefore < NotBefore) { NotBefore = certificate2.NotBefore; }
                if (NotAfter < certificate2.NotAfter) { NotAfter = certificate2.NotAfter; }
            }
        }

        public void Dispose()
        {
            if (Collection is { } collection)
            {
                var collectionToDispose = _collectionToDispose;

                Collection = null;
                _collectionToDispose = null;

                if (DisposeCertificates && ReferenceCounter == 0)
                {
                    YarpClientCertificateLoader.DisposeCertificates(collectionToDispose, null);
                }
                else
                {
                    // This will might lead to a memory leak. But we cannot dispose the certificates.
                    // Changes should not happen often. Once per month or so.
                }
            }
        }
    }

    /// <summary>
    /// Get the certificate collection based on the configuration.
    /// </summary>
    /// <param name="clientCertifiacteCollectionByTunnelId"></param>
    /// <param name="certificateCollectionFactory"></param>    
    /// <param name="configTunnelId"></param>
    /// <param name="loadWithPrivateKey">load with private key - or without if false.</param>
    /// <param name="certificateConfig"></param>
    /// <param name="listCertificateConfig"></param>
    /// <param name="x509CertificateCollection"></param>
    /// <param name="logger"></param>
    /// <returns></returns>
    public static YarpCertificateCollection GetCertificateCollection(
        ConcurrentDictionary<string, YarpCertificateCollection> clientCertifiacteCollectionByTunnelId,
        IYarpCertificateCollectionFactory certificateCollectionFactory,
        string configTunnelId,
        bool loadWithPrivateKey,
        CertificateConfig? certificateConfig,
        List<CertificateConfig>? listCertificateConfig,
        X509CertificateCollection? x509CertificateCollection,
        ILogger logger
        )
    {
        var certificateCollectionRequest = new LoadParameter(certificateConfig, listCertificateConfig, x509CertificateCollection);
        YarpCertificateCollection? clientCertifiacteCollection = null;
        while (clientCertifiacteCollection is null)
        {

            if (clientCertifiacteCollectionByTunnelId.TryGetValue(configTunnelId, out clientCertifiacteCollection))
            {
                if (!clientCertifiacteCollection.NeedsReload(certificateCollectionRequest)
                    // TODO: && clientCertifiacteCollection.IsValidDateRange()
                    )
                {
                    break;
                }

            }

            lock (clientCertifiacteCollectionByTunnelId)
            {
                if (clientCertifiacteCollectionByTunnelId.TryGetValue(configTunnelId, out clientCertifiacteCollection))
                {
                    if (!clientCertifiacteCollection.NeedsReload(certificateCollectionRequest)
                    // TODO: && clientCertifiacteCollection.IsValidDateRange()
                        )
                    {
                        break;
                    }
                }

                {
                    var nextClientCertifiacteCollection = certificateCollectionFactory.Create(configTunnelId, loadWithPrivateKey);
                    nextClientCertifiacteCollection.Load(certificateCollectionRequest);

                    if (clientCertifiacteCollection is null)
                    {
                        if (clientCertifiacteCollectionByTunnelId.TryAdd(configTunnelId, nextClientCertifiacteCollection))
                        {
                            logger.LogInformation("Certifactes loaded");
                            clientCertifiacteCollection = nextClientCertifiacteCollection;
                            break;
                        }
                        else
                        {
                            // the cert was added by another thread with in the lock... so we never get here?
                            nextClientCertifiacteCollection.Dispose();
                            clientCertifiacteCollection = null;
                        }
                    }
                    else
                    {
                        if (clientCertifiacteCollectionByTunnelId.TryUpdate(configTunnelId, nextClientCertifiacteCollection, clientCertifiacteCollection))
                        {
                            logger.LogInformation("Certifactes loaded");
                            clientCertifiacteCollection = nextClientCertifiacteCollection;
                            break;
                        }
                        else
                        {
                            // the cert was update by another thread with in the lock... so we never get here?
                            nextClientCertifiacteCollection.Dispose();
                            clientCertifiacteCollection = null;
                        }
                    }
                }
            }
        }

        return clientCertifiacteCollection;
    }

}
