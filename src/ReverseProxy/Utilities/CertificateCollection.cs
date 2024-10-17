#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

public class CertificateCollection
{
    private X509CertificateCollection? _collection;
    private readonly ICertificateLoader _certificateLoader;
    private readonly CertificatePathWatcher? _certificatePathWatcher;
    private readonly string _id;
    private IChangeToken? _changeToken;
    private Yarp.ReverseProxy.Configuration.CertificateConfig? _certificateConfig;
    private List<Yarp.ReverseProxy.Configuration.CertificateConfig>? _listCertificateConfig;


    public CertificateCollection(
        ICertificateLoader certificateLoader,
        CertificatePathWatcher? certificatePathWatcher,
        string id
        )
    {
        _collection = null;
        _certificateLoader = certificateLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _id = id;
        _changeToken = _certificatePathWatcher?.GetChangeToken();
    }

    public CertificateCollection Load(
        Yarp.ReverseProxy.Configuration.CertificateConfig? certificateConfig,
        List<Yarp.ReverseProxy.Configuration.CertificateConfig>? listCertificateConfig
        )
    {
        lock (this)
        {
            var refresh = HasChanged(certificateConfig, listCertificateConfig);

            if (refresh)
            {
                if (_collection is not null)
                {
                    ClientCertificateLoader.DisposeCertificates(_collection, null);
                    _collection = null;
                }
            }
            else
            {
                return this;
            }

            var state = new CertificateCollectionState(_certificateLoader, _certificatePathWatcher);
            {
                if (certificateConfig is { } certificateConfigItem)
                {
                    state.Load(certificateConfigItem, _id);
                }
            }
            if (listCertificateConfig is { Count: > 0 } authenticationClientCertificates)
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
            _collection = state.Collection;
            _certificateConfig = certificateConfig;
            _listCertificateConfig = listCertificateConfig?.ToList();
        }
        return this;
    }

    private bool HasChanged(CertificateConfig? certificateConfig, List<CertificateConfig>? listCertificateConfig)
    {
        var refresh = (_collection is null);

        if (_changeToken is { } changeToken
            && _changeToken.HasChanged)
        {
            _changeToken = _certificatePathWatcher?.GetChangeToken();
            refresh = true;

        }
        if (!refresh
            && !ReferenceEquals(_certificateConfig, certificateConfig)
            && _certificateConfig is not null
            && !_certificateConfig.Equals(certificateConfig))
        {
            refresh = true;
        }

        if (!refresh
            && !ReferenceEquals(_listCertificateConfig, listCertificateConfig)
            )
        {
            if (_listCertificateConfig is null
                && listCertificateConfig is null)
            {
            }
            else if (_listCertificateConfig is null
                || listCertificateConfig is null)
            {
                refresh = true;
            }
            else if (_listCertificateConfig.Count != listCertificateConfig.Count)
            {
                refresh = true;
            }
            else
            {
                for (var index = 0; index < _listCertificateConfig.Count; index++)
                {
                    if (!_listCertificateConfig[index].Equals(listCertificateConfig[index]))
                    {
                        refresh = true;
                        break;
                    }
                }
            }
        }

        return refresh;
    }

    public partial class CertificateCollectionState
    {
        private readonly ICertificateLoader _certificateLoader;
        private readonly CertificatePathWatcher? _certificatePathWatcher;

        public CertificateCollectionState(
            ICertificateLoader certificateLoader,
            CertificatePathWatcher? certificatePathWatcher
            )
        {
            _certificateLoader = certificateLoader;
            _certificatePathWatcher = certificatePathWatcher;
        }

        public readonly X509CertificateCollection Collection = new X509CertificateCollection();
        public DateTime NotBefore = DateTime.MaxValue;
        public DateTime NotAfter = DateTime.MinValue;

        public void Load(CertificateConfig certificateConfig, string keyname)
        {
            var (certificate, clientCertificateCollection) = _certificateLoader.LoadCertificateWithPrivateKey(certificateConfig, keyname);
            if (certificate is not null)
            {
                _ = Collection.Add(certificate);

                var certNotBefore = certificate.NotBefore;
                var certNotAfter = certificate.NotAfter;
                if (certNotBefore < NotBefore) { NotBefore = certNotBefore; }
                if (NotAfter < certNotAfter) { NotAfter = certNotAfter; }


                //certificate.NotAfter

                ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);

                if (certificateConfig.IsFileCert())
                {
                    _certificatePathWatcher?.AddWatch(certificateConfig);
                }
            }
            else
            {
                ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
            }
        }
    }

}
