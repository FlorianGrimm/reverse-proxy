using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;
#pragma warning disable IDE0032 // Use auto property

public class CertificateManager : ICertificateManager, ICertificateVerifier
{
    private readonly ILogger<CertificateManager> _logger;
    private List<ICertificateLoader> _certificateLoaders;

    private CertificateManagerOptions _options;

    private TimeSpan _cacheTimeSpan = TimeSpan.FromMinutes(5);
    private bool _allowSelfSigned;

    private X509RevocationMode _revocationMode = X509RevocationMode.Online;
    private X509VerificationFlags _verificationFlags = X509VerificationFlags.NoFlag;

    private Action<X509Certificate2, X509ChainPolicy>? _configureX509ChainPolicy;

    private ConcurrentDictionary<string, ListCertificateConfiguration> _certificates = new ConcurrentDictionary<string, ListCertificateConfiguration>();
    private readonly ConcurrentDictionary<string, ReferenceCountedCertificates> _loadedCertificate = new ConcurrentDictionary<string, ReferenceCountedCertificates>();


    public CertificateManager(
        IEnumerable<ICertificateLoader> certificateLoaders,
        IOptionsMonitor<CertificateManagerOptions> options,
        ILogger<CertificateManager> logger
        )
    {
        _certificateLoaders = certificateLoaders.ToList();
        _logger = logger;

        options.OnChange(OptionsOnChange);
        OptionsOnChange(_options = options.CurrentValue, default);
    }

    private void OptionsOnChange(CertificateManagerOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }

        _cacheTimeSpan = options.CacheTimeSpan;
        _allowSelfSigned = options.AllowSelfSigned;
        _configureX509ChainPolicy = options.ConfigureX509ChainPolicy;
        _revocationMode = options.RevocationMode;
        _verificationFlags = options.VerificationFlags;

        var certificates = new ConcurrentDictionary<string, ListCertificateConfiguration>(StringComparer.Ordinal);
        foreach (var (key, certificate) in options.Certificates)
        {
            certificates[key] = certificate;
        }
        _certificates = certificates;
        _options = options;

        foreach (var certificateLoader in _certificateLoaders)
        {
            certificateLoader.SetOptions(options);
            certificateLoader.SetCertificateVerifier(this);
        }
    }

    public List<ICertificateLoader> CertificateLoaders
    {
        get
        {
            return _certificateLoaders;
        }

        set
        {
            _certificateLoaders = value;
            foreach (var certificateLoader in _certificateLoaders)
            {
                certificateLoader.SetOptions(_options);
            }
        }
    }

    public ConcurrentDictionary<string, ListCertificateConfiguration> Certificates => _certificates;

    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    public ISharedValue<X509Certificate2Collection?> GetCertificateCollection(string certificateId)
    {
        while (true)
        {
            var localNow = TimeProvider.GetLocalNow();
            var cacheTimeLimit = localNow.Add(_cacheTimeSpan);
            ReferenceCountedCertificates? loadedCertificate;
            while (true)
            {
                if (_loadedCertificate.TryGetValue(certificateId, out loadedCertificate))
                {
                    if (loadedCertificate.IsWithInLimit(localNow))
                    {
                        lock (loadedCertificate)
                        {
                            var result = loadedCertificate.CreateSharedValue(localNow);
                            if (result is { }) { return result; }
                        }
                    }
                    break;
                }
                else
                {
                    loadedCertificate = new ReferenceCountedCertificates(TimeProvider);
                    if (_loadedCertificate.TryAdd(certificateId, loadedCertificate))
                    {
                        break;
                    }
                    else
                    {
                        continue;
                    }
                }
            }

            // load and set it
            {
                var certificateCollection = LoadCertificateCollection(certificateId);
                if (certificateCollection is null) { return new EmptySharedValue(); }

                lock (loadedCertificate)
                {
                    loadedCertificate.Set(certificateCollection, cacheTimeLimit);
                    var result = loadedCertificate.CreateSharedValue(localNow);
                    if (result is { }) { return result; }
                }
            }
        }
    }

    public X509Certificate2Collection? LoadCertificateCollection(string certificateId)
    {
        var localNow = TimeProvider.GetLocalNow().LocalDateTime;

        if (_certificates.TryGetValue(certificateId, out var listCertificateConfiguration))
        {
            X509Certificate2Collection? result = default;
            foreach (var certificateConfiguration in listCertificateConfiguration.Items)
            {
                var collection = LoadOneCertificate(certificateConfiguration, localNow);
                if (result is null)
                {
                    result = collection;
                }
                else if (collection is { })
                {
                    result.AddRange(collection);
                }
            }
            if (result is { })
            {
                if (result.Count <= 1)
                {
                    return result;
                }
                else
                {
                    // the certificate with latest notAfter and notBefore <= localNow <= notAfter
                    var certificate0 = result[0];
                    // var notBefore0 = certificate0.GetNotBeforeOrDefault(DateTime.MinValue);
                    var notAfter0 = certificate0.GetNotAfterOrDefault(DateTime.MinValue);
                    for (var index = 1; index < result.Count; index++)
                    {
                        var certificate = result[index];
                         var notBefore = certificate.GetNotBeforeOrDefault(DateTime.MinValue);
                        var notAfter = certificate.GetNotAfterOrDefault(DateTime.MaxValue);
                        if ((notBefore <= localNow && localNow <= notAfter)
                            && (notAfter0 < notAfter))
                        {
                            result[0] = certificate;
                            result[index] = certificate0;
                            certificate0 = certificate;
                            notAfter0 = notAfter;
                        }
                    }
                }
            }
        }
        return null;
    }

    public X509Certificate2Collection? LoadOneCertificate(
        CertificateConfiguration certificateConfiguration,
        DateTime localNow)
    {
        foreach (var certificateLoader in _certificateLoaders)
        {
            var (matchedLoader, collection) = certificateLoader.LoadCertificate(certificateConfiguration, localNow);
            if (matchedLoader)
            {
                return collection;
            }
        }
        return null;
    }

    public bool ValidateCertificate(X509Certificate2 certificate, DateTime localNow)
    {
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.VerificationTime = localNow;
            if (_allowSelfSigned && certificate.IsSelfSignedCertificate())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(certificate);
            }
            else
            {
                chain.ChainPolicy.RevocationMode = _revocationMode;
                chain.ChainPolicy.VerificationFlags = _verificationFlags;
            }
            if (_configureX509ChainPolicy is { } configureX509ChainPolicy)
            {
                configureX509ChainPolicy(certificate, chain.ChainPolicy);
            }
            var result = chain.Build(certificate);
            if (!result)
            {
                if (_logger.IsEnabled(LogLevel.Debug))
                {
                    _logger.LogDebug("Certificate: {Subject} not valid.", certificate.Subject);
                    foreach (var chainStatus in chain.ChainStatus)
                    {
                        _logger.LogDebug("{Status}-{StatusInformation}", chainStatus.Status, chainStatus.StatusInformation);
                    }
                }
            }
            return result;
        }
    }

    private sealed class ReferenceCountedCertificates
    {
        private X509Certificate2Collection? _certificateCollection;
        private DateTimeOffset _cacheTimeLimit;
        private long _referenceCounter;
        private bool _givenAway;
        private readonly TimeProvider _timeProvider;

        internal ReferenceCountedCertificates(
            TimeProvider timeProvider
            )
        {
            _certificateCollection = null;
            _cacheTimeLimit = System.DateTimeOffset.MinValue;
            _referenceCounter = 0L;
            _timeProvider = timeProvider;
        }

        internal void Set(X509Certificate2Collection certificateCollection, DateTimeOffset cacheTimeLimit)
        {
            _certificateCollection = certificateCollection;
            _cacheTimeLimit = cacheTimeLimit;
            _referenceCounter = 0L;
        }

        internal bool IsWithInLimit(DateTimeOffset localNow)
            => (_certificateCollection is { } && !_givenAway && (localNow <= _cacheTimeLimit));

        internal ISharedValue<X509Certificate2Collection?>? CreateSharedValue(DateTimeOffset localNow)
        {
            if (IsWithInLimit(localNow)
                && _certificateCollection is { } certificateCollection)
            {
                System.Threading.Interlocked.Increment(ref _referenceCounter);
                var result = new SharedValueX509Certificate2Collection(certificateCollection, this);
                return result;
            }
            else
            {
                return default;
            }
        }

        internal void HandleGiveAway(X509Certificate2Collection? collection)
        {
            lock (this)
            {
                if (ReferenceEquals(collection, _certificateCollection))
                {
                    _givenAway = true;
                    _certificateCollection = default;
                }
            }
        }

        internal void HandleDispose(X509Certificate2Collection collection)
        {
            lock (this)
            {
                if (_givenAway)
                {
                    // nothing todo
                }
                else if (ReferenceEquals(collection, _certificateCollection))
                {
                    if (System.Threading.Interlocked.Decrement(ref _referenceCounter) <= 0)
                    {
                        if (_timeProvider.GetLocalNow() < _cacheTimeLimit)
                        {
                            // still good
                        }
                        else
                        {
                            _certificateCollection = null;
                            collection.DisposeCertificatesExcept();
                        }
                    }
                }
            }
        }

    }

    private sealed class EmptySharedValue : ISharedValue<X509Certificate2Collection?>
    {
        public X509Certificate2Collection? Value => null;
        public X509Certificate2Collection? GiveAway() => null;
        public void Dispose() { }
    }

    private sealed class SharedValueX509Certificate2Collection : ISharedValue<X509Certificate2Collection?>
    {
        private X509Certificate2Collection? _value;
        private ReferenceCountedCertificates? _owner;

        public SharedValueX509Certificate2Collection(X509Certificate2Collection value, ReferenceCountedCertificates owner)
        {
            _value = value;
            _owner = owner;
        }

        public X509Certificate2Collection? Value => _value;

        public X509Certificate2Collection? GiveAway()
        {
            if (_value is { } value && _owner is { } owner)
            {
                _value = default;
                _owner = default;
                owner.HandleGiveAway(value);
                return value;
            }
            return null;
        }

        public void Dispose()
        {
            if (_value is { } value && _owner is { } owner)
            {
                _value = default;
                _owner = default;
                owner.HandleDispose(value);
            }
        }
    }
}

