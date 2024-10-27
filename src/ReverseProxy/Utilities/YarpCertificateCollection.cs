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
public sealed class YarpCertificateCollection
    : IDisposable
{
    private readonly IYarpCertificateLoader _certificateLoader;
    private readonly YarpCertificatePathWatcher? _certificatePathWatcher;
    private readonly string _id;
    private readonly bool _loadWithPrivateKey;
    private LoadParameter? _currentParameter;
    private State? _currentState;

    /// <summary>
    /// Guess what a constructor does.
    /// </summary>
    /// <param name="certificateLoader">The certificate loader</param>
    /// <param name="certificatePathWatcher">The filewatche</param>
    /// <param name="id">A id - like the cluster id</param>
    /// <param name="loadWithPrivateKey">load with private key.</param>
    public YarpCertificateCollection(
        IYarpCertificateLoader certificateLoader,
        YarpCertificatePathWatcher? certificatePathWatcher,
        string id,
        bool loadWithPrivateKey = true
        )
    {
        _certificateLoader = certificateLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _id = id;
        _loadWithPrivateKey = loadWithPrivateKey;
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

    public Shared<X509CertificateCollection?> Share()
    {
        if (_currentState is { } currentState
            && currentState.Collection is { } result)
        {
            currentState.ReferenceCounter++;

            return new Shared<X509CertificateCollection?>(
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
            return new Shared<X509CertificateCollection?>(
                default,
                (value, _) => { });
        }

    }

    public bool TryGet(
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
    public YarpCertificateCollection Load(
        LoadParameter parameter
        )
    {
        {
            // fast path if not changed
            var refresh = (_currentState is null) || HasChanged(parameter);
            if (!refresh) { return this; }
        }
        {
            var previousState = _currentState;
            lock (this)
            {
                {
                    // test again after lock
                    var refresh = (_currentState is null) || HasChanged(parameter);
                    if (!refresh) { return this; }
                }
                {
                    State state = (_loadWithPrivateKey)
                        ? new StateWithPrivateKey(_certificateLoader, _certificatePathWatcher)
                        : new StateNoPrivateKey(_certificateLoader, _certificatePathWatcher);

                    {
                        if (parameter.CertificateConfig is { } certificateConfigItem)
                        {
                            state.Load(certificateConfigItem, _id);
                        }
                    }

                    if (parameter.ListCertificateConfig is { Count: > 0 } authenticationClientCertificates)
                    {
                        for (var index = 0; index < authenticationClientCertificates.Count; index++)
                        {
                            if (authenticationClientCertificates[index] is { } certificateConfigItem)
                            {
                                var keyname = $"{_id}-{index}";
                                state.Load(certificateConfigItem, keyname);
                            }
                        }
                    }
                    if (parameter.X509CertificateCollection is { } x509CertificateCollection)
                    {
                        state.AddShared(x509CertificateCollection);
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

    public bool HasChanged(LoadParameter nextCertificateCollectionRequest)
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

        if (!AreEqualCertificateConfig(currentCertificateCollectionRequest.CertificateConfig, nextCertificateCollectionRequest.CertificateConfig))
        {
            return true;
        }

        return !AreEqualListCertificateConfig(currentCertificateCollectionRequest.ListCertificateConfig, nextCertificateCollectionRequest.ListCertificateConfig);
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

    public partial record struct LoadParameter(
        CertificateConfig? CertificateConfig,
        List<CertificateConfig>? ListCertificateConfig,
        X509CertificateCollection? X509CertificateCollection);

    internal abstract partial class State(
        IYarpCertificateLoader certificateLoader,
        YarpCertificatePathWatcher? certificatePathWatcher
        ) : IDisposable
    {
        private readonly IYarpCertificateLoader _certificateLoader = certificateLoader;
        private readonly YarpCertificatePathWatcher? _certificatePathWatcher = certificatePathWatcher;

        private X509CertificateCollection? _collectionToDispose;

        public IChangeToken? CertificateChangeToken { get; private set; }
        public X509CertificateCollection? Collection { get; private set; }

        // TODO: Test if we can automagic use the valid certifcate (within the date range)
        public DateTime NotBefore = DateTime.MaxValue;
        public DateTime NotAfter = DateTime.MinValue;

        public int ReferenceCounter = 0;
        public bool DisposeCertificates = true;

        /// <summary>
        /// Load the certificates defined by the config
        /// </summary>
        /// <param name="certificateConfig">the configuration that specifies the certificates to load.</param>
        /// <param name="keyname"></param>
        public abstract void Load(
            CertificateConfig certificateConfig,
            string keyname);

        protected void PostLoad(
            CertificateConfig certificateConfig,
            X509Certificate2? certificate,
            X509Certificate2Collection? clientCertificateCollection)
        {
            if (certificate is not null)
            {
                if (Collection is null)
                {
                    _collectionToDispose = Collection = new X509CertificateCollection();
                }
                Collection.Add(certificate);

                var certNotBefore = certificate.NotBefore;
                var certNotAfter = certificate.NotAfter;
                if (certNotBefore < NotBefore) { NotBefore = certNotBefore; }
                if (NotAfter < certNotAfter) { NotAfter = certNotAfter; }

                YarpClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                if (certificateConfig.IsFileCert())
                {
                    _certificatePathWatcher?.AddWatch(certificateConfig);

                    if (CertificateChangeToken is null
                        && _certificatePathWatcher is { } certificatePathWatcher)
                    {
                        CertificateChangeToken = certificatePathWatcher.GetChangeToken();
                    }
                }
            }
            else
            {
                YarpClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
            }           
        }

        internal void AddShared(X509CertificateCollection x509CertificateCollection)
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
                nextCollection.Add(certificate);
                if (certificate is X509Certificate2 certificate2)
                {
                    if (certificate2.NotBefore < NotBefore) { NotBefore = certificate2.NotBefore; }
                    if (NotAfter < certificate2.NotAfter) { NotAfter = certificate2.NotAfter; }
                }
            }
            Collection = nextCollection;
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

        internal partial class StateWithPrivateKey(
                IYarpCertificateLoader certificateLoader,
                YarpCertificatePathWatcher? certificatePathWatcher
            ) : State(
                certificateLoader,
                certificatePathWatcher
            )
        {
            public override void Load(CertificateConfig certificateConfig, string keyname)
            {
                var (certificate, clientCertificateCollection) = _certificateLoader.LoadCertificateWithPrivateKey(certificateConfig, keyname);
                PostLoad(certificateConfig, certificate, clientCertificateCollection);
            }
        }

        internal partial class StateNoPrivateKey(
                IYarpCertificateLoader certificateLoader,
                YarpCertificatePathWatcher? certificatePathWatcher
            ) : State(
                certificateLoader,
                certificatePathWatcher
            )
        {
            public override void Load(CertificateConfig certificateConfig, string keyname)
            {
                var (certificate, clientCertificateCollection) = _certificateLoader.LoadCertificateNoPrivateKey(certificateConfig, keyname);
                PostLoad(certificateConfig, certificate, clientCertificateCollection);
            }
        }
    }


    public static YarpCertificateCollection GetCertificateCollection(
        ConcurrentDictionary<string, YarpCertificateCollection> clientCertifiacteCollectionByTunnelId,
        IYarpCertificateLoader certificateLoader,
        YarpCertificatePathWatcher? certificatePathWatcher,
        string configTunnelId,

        CertificateConfig? certificateConfig,
        List<CertificateConfig>? listCertificateConfig,
        X509CertificateCollection? x509CertificateCollection,
        ILogger logger
        ) => GetCertificateCollection(
            clientCertifiacteCollectionByTunnelId,
            certificateLoader,
            certificatePathWatcher,
            configTunnelId,
            new LoadParameter(certificateConfig, listCertificateConfig, x509CertificateCollection),
            logger
            );

    public static YarpCertificateCollection GetCertificateCollection(
        ConcurrentDictionary<string, YarpCertificateCollection> clientCertifiacteCollectionByTunnelId,
        IYarpCertificateLoader certificateLoader,
        YarpCertificatePathWatcher? certificatePathWatcher,
        string configTunnelId,
        YarpCertificateCollection.LoadParameter certificateCollectionRequest,
        ILogger logger
        )
    {
        YarpCertificateCollection? clientCertifiacteCollection = null;
        while (clientCertifiacteCollection is null)
        {

            if (clientCertifiacteCollectionByTunnelId.TryGetValue(configTunnelId, out clientCertifiacteCollection))
            {
                if (!clientCertifiacteCollection.HasChanged(certificateCollectionRequest)
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
                    if (!clientCertifiacteCollection.HasChanged(certificateCollectionRequest)
                    // TODO: && clientCertifiacteCollection.IsValidDateRange()
                        )
                    {
                        break;
                    }
                }

                {
                    var nextClientCertifiacteCollection = new YarpCertificateCollection(
                        certificateLoader, certificatePathWatcher, configTunnelId, true);
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
