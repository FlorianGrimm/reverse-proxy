using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// This class is responsible for managing (loading) certificates.
/// First you create a CertificateRequest and then you add it to the manager - AddRequest.
/// Than you can use GetCertificateCollection to retrive the certificate(s).
/// After a refresh time / or the filewatcher notified a changes the certificate(s) will be reloaded and compared.
/// If nothing changed the old certificate(s) will be returned (and the new one disposed).
/// If something changed the new certificate(s) will be returned (and the old one disposed after a cool down time).
/// If the certificates reaching the end of their lifetime a refresh will be triggered.
/// If the certificates are known to be used by a service that cannot be refreshed you have to avoid the dispose.
/// </summary>
public partial class CertificateManager
    : IDisposable
{
    private readonly ConcurrentDictionary<string, Timestamped<X509Certificate2Collection>> _previousRequestCollection = new();
    private readonly ConcurrentDictionary<string, CertificateRequestCollection> _currentRequestCollection = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _previousByRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _loadedByRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateCurrentCertificate> _currentByRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, int> _ghostGenerationRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateCurrentCertificate> _cooldownByRequest = new();
    private readonly ConcurrentDictionary<string, string> _certificateFilewatcher = new();
    private readonly ConcurrentDictionary<CertificateStoreLocationName, CertificateStoreLocationName> _certificateStoreLocationNames = new();
    private IDisposable? _unwireOptionsOnChange;
    private CertificateManagerFileWatcher _fileWatcher;
    private CancellationTokenSource? _ctsRefresh;
    private int _generationsUntilSleep = 10;
    private string? _certificateRootPath;
    private readonly StateReload _stateReload;
    private readonly ILogger<CertificateManager> _logger;
    private readonly ICertificatePasswordProvider _certificatePasswordProvider;

    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan CoolDownTime { get; set; } = TimeSpan.FromMinutes(10);

    public int GenerationsUntilSleep { get => _generationsUntilSleep; set => _generationsUntilSleep = value > 3 ? value : 3; }

    public string? CertificateRootPath
    {
        get => _certificateRootPath;
        set
        {
            _certificateRootPath = value;
            if (FileCertificateLoader is { } loader)
            {
                loader.CertificateRootPath = value;
            }
        }
    }

    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    // TODO
    public ICertificateFileLoader FileCertificateLoader { get; set; }

    public CertificateManager(
        ICertificatePasswordProvider certificatePasswordProvider,
        ILogger<CertificateManager> logger)
    {
        _stateReload = new StateReload(this);
        _certificatePasswordProvider = certificatePasswordProvider;
        _logger = logger;
        _fileWatcher = new CertificateManagerFileWatcher(CertificateRootPath ?? ".", logger, null);
        FileCertificateLoader = new CertificateFileLoader(
            CertificateRootPath ?? ".",
            _certificatePasswordProvider, logger);
    }

    public CertificateManager(
        IOptionsMonitor<CertificateManagerOptions> options,
        ICertificatePasswordProvider certificatePasswordProvider,
        ILogger<CertificateManager> logger
        )
    {
        _stateReload = new StateReload(this);
        _certificatePasswordProvider = certificatePasswordProvider;
        _logger = logger;
        onOptionsChanged(options.CurrentValue, null);
        _unwireOptionsOnChange = options.OnChange(onOptionsChanged);
        _fileWatcher = new CertificateManagerFileWatcher(CertificateRootPath ?? ".", logger, null);
        FileCertificateLoader = new CertificateFileLoader(CertificateRootPath ?? ".", _certificatePasswordProvider, logger);
    }

    private void onOptionsChanged(CertificateManagerOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }
        RefreshInterval = options.RefreshInterval;
        CoolDownTime = options.CoolDownTime;
        if (options.CertificateRootPath is { } certificateRootPath)
        {
            if (!string.Equals(CertificateRootPath, certificateRootPath, StringComparison.CurrentCultureIgnoreCase))
            {
                CertificateRootPath = certificateRootPath;
                lock (_stateReload)
                {
                    _stateReload.SetIsLoadNeeded();
                }
            }
        }
    }

    public CertificateRequestCollection AddConfiguration(
        string id,
        CertificateConfig? certificateConfig,
        List<CertificateConfig>? certificateConfigs,
        X509Certificate2Collection? x509Certificate2s,
        CertificateRequirement requirement)
    {
        var certificateRequests = new List<CertificateRequest>();
        if (certificateConfig is { })
        {
            var request = new CertificateRequest(certificateConfig, requirement);
            certificateRequests.Add(request);
            AddRequest(request);
        }
        if (certificateConfigs is { })
        {
            foreach (var item in certificateConfigs)
            {
                var request = new CertificateRequest(item, requirement);
                certificateRequests.Add(request);
                AddRequest(request);
            }
        }
        var result = new CertificateRequestCollection(id, certificateRequests, x509Certificate2s);
        AddRequestCollection(result);
        return result;
    }

    public void AddRequestCollection(CertificateRequestCollection result)
    {
        if (_currentRequestCollection.TryGetValue(result.Id, out var current))
        {
            if (current != result)
            {
                _currentRequestCollection.TryUpdate(result.Id, result, current);
            }
        }
        else
        {
            _currentRequestCollection.TryAdd(result.Id, result);
        }
    }

    public CertificateRequest AddRequest(CertificateRequest request)
    {

        if (!request.IsStoreCert() || !request.IsFileCert())
        {
            throw new ArgumentException("The CertificateRequest must be a store or a file certificate.", nameof(request));
        }

        if (!string.IsNullOrEmpty(request.Path))
        {
            string fullPath;
            if (!System.IO.Path.IsPathFullyQualified(request.Path))
            {
                fullPath = System.IO.Path.Combine(CertificateRootPath ?? ".", request.Path);
                request = request with { Path = fullPath };
            }
        }
        if (!string.IsNullOrEmpty(request.KeyPath))
        {
            string fullPath;
            if (!System.IO.Path.IsPathFullyQualified(request.KeyPath))
            {
                fullPath = System.IO.Path.Combine(CertificateRootPath ?? ".", request.KeyPath);
                request = request with { KeyPath = fullPath };
            }
        }

        if (!_currentByRequest.ContainsKey(request))
        {
            if (_currentByRequest.TryAdd(request, new StateCurrentCertificate()))
            {
                _ghostGenerationRequest[request] = 0;
                lock (_stateReload)
                {
                    _stateReload.SetIsLoadNeeded();
                }
            }
        }

        return request;
    }

    public X509Certificate2Collection? GetCertificateCollection(CertificateRequest request)
    {
        // ensure the certificates are loaded
        {
            if (IsAwakeNeeded(request))
            {
                Refresh(true);
            }
            else
            {
                Refresh(false);
            }
        }

        // get the certificates and return them
        {
            _ghostGenerationRequest[request] = 0;

            if (_currentByRequest.TryGetValue(request, out var state))
            {
                return state.GetCertificateCollection();
            }
        }

        // or return null
        return null;
    }

    public X509Certificate2Collection? GetCertificateCollection(CertificateRequestCollection requestCollection)
    {
        if (requestCollection.CertificateRequests.Count == 0)
        {
            return requestCollection.X509Certificate2s;
        }
        else
        {
            var refresh = false;
            if (_previousRequestCollection.TryGetValue(requestCollection.Id, out var timestampedResult))
            {
                if (timestampedResult.Timestamp == _stateReload.Changed)
                {
                    foreach (var request in requestCollection.CertificateRequests)
                    {
                        if (IsAwakeNeeded(request))
                        {
                            refresh = true;
                        }
                        else
                        {
                            _ghostGenerationRequest[request] = 0;
                        }
                    }
                    if (refresh)
                    {
                        _stateReload.SetIsLoadNeeded();
                    }
                    else
                    {
                        return timestampedResult.Value;
                    }
                }
            }

            // collect the certificates
            var result = new X509Certificate2Collection();
            var timestamp = _stateReload.Changed;
            foreach (var request in requestCollection.CertificateRequests)
            {
                _ghostGenerationRequest[request] = 0;

                if (GetCertificateCollection(request) is { } collection)
                {
                    result.AddRange(collection);
                }
            }
            if (requestCollection.X509Certificate2s is { } certs)
            {
                result.AddRange(certs);
            }
            timestampedResult = new Timestamped<X509Certificate2Collection>(result, timestamp);
            _previousRequestCollection[requestCollection.Id] = timestampedResult;
            return result;
        }
    }

    /// <summary>
    /// Refresh(reload) the certificates.
    /// </summary>
    /// <param name="force">false - only if needed; true - always</param>
    public void Refresh(bool force)
    {
        if (force || _stateReload.IsLoadNeeded())
        {
            lock (_stateReload)
            {
                try
                {
                    IncrementGhostGenerationRequest();
                    LoadStoreCertificates();
                    LoadFileCertificates();
                    PostLoadHandleChanges();
                    _stateReload.SetIsLoadNeeded(false);
                    StartRefresh();
                }
                catch (System.Exception error)
                {
                    _logger.LogError(error, "Refresh failed");
                }
            }
        }
    }

    private void IncrementGhostGenerationRequest()
    {
        foreach (var request in _currentByRequest.Keys.ToList())
        {
            if (_ghostGenerationRequest.TryGetValue(request, out var counter))
            {
                if (counter < _generationsUntilSleep)
                {
                    _ghostGenerationRequest[request] = counter + 1;
                }
                else
                {
                    // TODO: unwire the file watcher
                }
            }
            else
            {
                _ghostGenerationRequest[request] = 2;
            }
        }
    }

    private bool IsAwakeNeeded(CertificateRequest request)
    {
        if (_ghostGenerationRequest.TryGetValue(request, out var counter))
        {
            if (_generationsUntilSleep <= counter)
            {
                return true;
            }
            return false;
        }
        else
        {
            _ghostGenerationRequest[request] = _generationsUntilSleep;
            return true;
        }
    }

    private void StartRefresh()
    {
        if (_ctsRefresh is { }) { return; }
        _ctsRefresh = new CancellationTokenSource();

        var ctStop = _ctsRefresh.Token;
        Task.Run(async () =>
        {
            while (ctStop.IsCancellationRequested)
            {
                await Task.Delay(RefreshInterval, ctStop);
                lock (_stateReload)
                {
                    if (!_stateReload.IsLoadNeeded()) { continue; }
                    {
                        try
                        {
                            LoadStoreCertificates();
                            LoadFileCertificates();
                            PostLoadHandleChanges();
                        }
                        catch (System.Exception error)
                        {
                            _logger.LogError(error, "Refresh failed");
                        }
                    }
                }

            }
        }, ctStop).ContinueWith((t) =>
        {
            if (t.IsFaulted)
            {
                _logger.LogError(t.Exception, "StartRefresh failed");
            }
            using (var ctsRefresh = _ctsRefresh)
            {
                _ctsRefresh = null;
            }
        });

    }

    private void LoadStoreCertificates()
    {
        Dictionary<CertificateStoreLocationName, List<CertificateRequest>> requestsByStoreLocationName = new();

        foreach (var request in _currentByRequest.Keys.ToList())
        {
            if (request.IsStoreCert() && request.StoreLocationName is { } storeLocationName)
            {
                if (!requestsByStoreLocationName.TryGetValue(storeLocationName, out var requests))
                {
                    requests = new List<CertificateRequest>();
                    requestsByStoreLocationName.Add(storeLocationName, requests);
                }
                requests.Add(request);
            }
        }

        // load from store
        {
            foreach (var (storeLocationName, requests) in requestsByStoreLocationName)
            {
                using (var store = new X509Store(storeLocationName.StoreName, storeLocationName.StoreLocation))
                {
                    X509Certificate2Collection? storeCertificates = null;

                    try
                    {
                        store.Open(OpenFlags.ReadOnly);
                        storeCertificates = store.Certificates;
                        for (var i = storeCertificates.Count - 1; 0 <= i; i--)
                        {
                            var certificate = storeCertificates[i];
                            // check which CertificateRequest is interested in this certificate
                            var isInterested = false;

                            foreach (var request in requests)
                            {
                                if (DoesStoreCertificateMatchesRequest(request, certificate))
                                {
                                    isInterested = true;
                                    if (!_loadedByRequest.TryGetValue(request, out var stateLoaded))
                                    {
                                        stateLoaded = new StateLoadedCertificate(request);
                                        _loadedByRequest.TryAdd(request, stateLoaded);
                                    }
                                    stateLoaded.Add(certificate);
                                }
                            }

                            if (isInterested)
                            {
                                storeCertificates.RemoveAt(i);
                            }
                            else
                            {
                                // if no CertificateRequest is interested in this certificate dispose it finally
                            }
                        }

                    }
                    finally
                    {
                        if (storeCertificates is { })
                        {
                            for (var i = 0; i < storeCertificates.Count; i++) { storeCertificates[i].Dispose(); }
                        }
                    }
                }
            }
        }

        // finally set the timestamp
        _stateReload.StoreLoaded = TimeProvider.GetUtcNow();
    }

    private void LoadFileCertificates()
    {
        Dictionary<string, List<CertificateRequest>> requestsByFilename = new();

        foreach (var request in _currentByRequest.Keys.ToList())
        {
            if (!string.IsNullOrEmpty(request.Path))
            {
                if (!requestsByFilename.TryGetValue(request.Path, out var requests))
                {
                    requests = new List<CertificateRequest>();
                    requestsByFilename.Add(request.Path, requests);
                }
                requests.Add(request);
            }
        }

        // load from file
        {
            foreach (var (filename, requests) in requestsByFilename)
            {
                var certificateCollection = LoadCertificateFromFile(requests);
                // check which CertificateRequest is interested in this certificate
                var isInterested = false;
                foreach (var request in requests)
                {
                    if (certificateCollection is { })
                    {
                        foreach (var itemCertificate in certificateCollection)
                        {
                            check(request, itemCertificate);
                        }
                    }
                }
                if (!isInterested)
                {
                    // if no CertificateRequest is interested in this certificate dispose it finally
                    certificateCollection.DisposeCertificates(default);
                }

                void check(CertificateRequest request, X509Certificate2 certificate)
                {
                    if (DoesFileCertificateMatchesRequest(request, certificate))
                    {
                        isInterested = true;
                        if (!_loadedByRequest.TryGetValue(request, out var stateLoaded))
                        {
                            stateLoaded = new StateLoadedCertificate(request);
                            _loadedByRequest.TryAdd(request, stateLoaded);
                        }
                        stateLoaded.Add(certificate);
                    }
                }
            }
        }

        // finally set the timestamp
        _stateReload.FileLoaded = TimeProvider.GetUtcNow();
    }

    private void PostLoadHandleChanges()
    {
        var changed = false;
        var loaded = _stateReload.Loaded;
        foreach (var request in _loadedByRequest.Keys)
        {
            if (_loadedByRequest.TryRemove(request, out var stateLoaded))
            {
                if (PostLoadHandleChangesForOne(request, stateLoaded, loaded))
                {
                    changed = true;
                }
            }
        }
        if (changed)
        {
            _stateReload.TriggerIsDisposePastNeeded();
            _stateReload.Changed = _stateReload.Loaded;
        }
    }

    private bool PostLoadHandleChangesForOne(CertificateRequest request, StateLoadedCertificate stateLoaded, DateTimeOffset loaded)
    {
        // check if the certificate is matches _previousByRequest

        if (_previousByRequest.TryGetValue(request, out var statePrevious))
        {
            var isSame = (statePrevious.Certificates.Count == stateLoaded.Certificates.Count);
            if (isSame)
            {
                for (var i = 0; i < stateLoaded.Certificates.Count; i++)
                {
                    if (!string.Equals(
                        stateLoaded.Certificates[i].Thumbprint,
                        statePrevious.Certificates[i].Thumbprint,
                        StringComparison.Ordinal))
                    {
                        isSame = false;
                        break;
                    }
                }
            }
            if (isSame /* and previous exists */)
            {
                // if the certificate is the same as before
                // dispose the new certificate and use the old one
                foreach (var certificate in stateLoaded.Certificates)
                {
                    certificate.Dispose();
                }
                stateLoaded.Certificates.Clear();
                _loadedByRequest.TryRemove(request, out _);
                return false;
            }
            else
            {
                // if the certificate(s) are different                
                _previousByRequest.TryAdd(request, stateLoaded);
            }
        }
        else
        {
            // if the certificate(s) are new
            _previousByRequest.TryAdd(request, stateLoaded);
        }

        // if the certificate(s) are new or different
        var stateCurrent = new StateCurrentCertificate(stateLoaded.Certificates);
        if (_currentByRequest.TryGetValue(request, out var oldStateCurrent))
        {
            _currentByRequest[request] = stateCurrent;
            _cooldownByRequest[request] = oldStateCurrent;
        }
        else
        {
            _currentByRequest[request] = stateCurrent;
        }
        return true;
    }

    public bool DoesStoreCertificateMatchesRequest(CertificateRequest request, X509Certificate2 certificate)
    {
        if (request.Subject is { Length: > 0 } subject)
        {
            if (!string.Equals(certificate.Subject, subject, StringComparison.OrdinalIgnoreCase)) { return false; }
        }
        return DoesAnyCertificateMatchesRequest(request, certificate);
    }

    public bool DoesFileCertificateMatchesRequest(CertificateRequest request, X509Certificate2 certificate)
    {
        return DoesAnyCertificateMatchesRequest(request, certificate);
    }

    public bool DoesAnyCertificateMatchesRequest(CertificateRequest request, X509Certificate2 certificate)
    {

        if (request.Requirement.NeedPrivateKey)
        {
            if (!certificate.HasPrivateKey)
            {
                return false;
            }
        }
        if (request.Requirement.ClientCertificate)
        {
            if (!certificate.IsCertificateAllowedForClientCertificate())
            {
                return false;
            }
        }
        if (request.Requirement.SignCertificate)
        {
            if (!certificate.IsCertificateAllowedForX509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature))
            {
                return false;
            }
        }
        using (X509Chain chain = new())
        {
            if (request.Requirement.RevocationMode.HasValue)
            {
                chain.ChainPolicy.RevocationMode = request.Requirement.RevocationMode.Value;
            }
            if (request.Requirement.RevocationFlag.HasValue)
            {
                chain.ChainPolicy.RevocationFlag = request.Requirement.RevocationFlag.Value;
            }
            if (request.Requirement.VerificationFlags.HasValue)
            {
                chain.ChainPolicy.VerificationFlags = request.Requirement.VerificationFlags.Value;
            }
            chain.ChainPolicy.VerificationTime = TimeProvider.GetUtcNow().DateTime;
#if NET7_0_OR_GREATER
            chain.ChainPolicy.VerificationTimeIgnored = false;
#endif
            if (!chain.Build(certificate))
            {
                return false;
            }
            foreach (var chainStatus in chain.ChainStatus)
            {
                if (chainStatus.Status == X509ChainStatusFlags.RevocationStatusUnknown)
                {
                    continue;
                }
                return false;
            }
            return true;
        }
    }

    private void DisposePastAfterCoolDown()
    {
        foreach (var request in _cooldownByRequest.Keys)
        {
            if (_cooldownByRequest.TryRemove(request, out var stateCooldown))
            {
                stateCooldown.DisposeCoolDown();
            }
        }
    }

    public void Dispose()
    {
        // since this is a singleton this will be rearly called (in production).
        _ctsRefresh?.Cancel();

        using (var optionsOnChange = _unwireOptionsOnChange)
        {
            _unwireOptionsOnChange = null;
        }
    }

    internal void RemoveRequest(CertificateRequest request)
    {
        throw new NotImplementedException();
    }

    internal class StateReload
    {
        private readonly CertificateManager _certificateManager;
        private bool _isLoadNeededNow;
        private DateTimeOffset? _isLoadNeedRefreshTime;
        private DateTimeOffset? _isDisposePastNeeded;
        private DateTimeOffset _storeLoaded;
        private DateTimeOffset _fileLoaded;

        internal DateTimeOffset StoreLoaded { get => _storeLoaded; set { _storeLoaded = Loaded = value; } }
        internal DateTimeOffset FileLoaded { get => _fileLoaded; set { _fileLoaded = Loaded = value; } }

        internal DateTimeOffset Loaded;

        internal DateTimeOffset Changed;

        public StateReload(CertificateManager certificateManager)
        {
            _certificateManager = certificateManager;
        }

        public DateTimeOffset GetUtcNow() => _certificateManager.TimeProvider.GetUtcNow();

        internal void SetIsLoadNeeded(bool value = true)
        {
            if (_isLoadNeededNow == value) { return; }
            _isLoadNeededNow = value;

            SetIsLoadedNeededRefreshTime();
        }

        private void SetIsLoadedNeededRefreshTime()
        {
            var next = _certificateManager.TimeProvider.GetUtcNow()
                            .Add(_certificateManager.RefreshInterval);
            _isLoadNeedRefreshTime = next;
        }

        internal bool IsLoadNeeded()
        {
            if (_isLoadNeededNow) { return true; }

            var utcNow = _certificateManager.TimeProvider.GetUtcNow();
            if (_isLoadNeedRefreshTime.HasValue && _isLoadNeedRefreshTime.Value <= utcNow) { return true; }

            return false;
        }

        /// <summary>
        /// Trigger the dispose of the past certificates after the cool down time.
        /// </summary>
        internal void TriggerIsDisposePastNeeded()
        {
            // set the time when the dispose should be done
            {
                var utcNow = _certificateManager.TimeProvider.GetUtcNow();
                var utcLimit = utcNow.Add(_certificateManager.CoolDownTime);
                if (_isDisposePastNeeded.HasValue)
                {
                    return;
                }
                _isDisposePastNeeded = utcLimit;
            }

            // start a task to dispose the past certificates
            {
                Task.Run(async () =>
                {
                    while (true)
                    {
                        var d = _isDisposePastNeeded;
                        if (!d.HasValue) { return; }

                        var now = _certificateManager.TimeProvider.GetUtcNow();
                        if (now < d.Value)
                        {
                            var wait = d.Value - now;
                            if (wait > TimeSpan.Zero)
                            {
                                await Task.Delay(wait);
                                continue;
                            }
                        }
                        break;
                    }
                    _isDisposePastNeeded = default;
                    _certificateManager.DisposePastAfterCoolDown();
                }).ContinueWith((t) =>
                {
                    if (t.IsFaulted)
                    {
                        _certificateManager._logger.LogError(t.Exception, "DisposePastAfterCoolDown failed");
                    }
                });
            }
        }

        internal bool IsDisposePastNeeded() => _isDisposePastNeeded.HasValue;
    }


    internal class StateLoadedCertificate
    {
        private readonly CertificateRequest _request;
        internal readonly X509Certificate2Collection Certificates = new();

        public StateLoadedCertificate(CertificateRequest request)
        {
            _request = request;
        }

        internal void Add(X509Certificate2 certificate)
        {
            Certificates.Add(certificate);
        }
    }

    internal class StateCurrentCertificate
    {
        private X509Certificate2Collection? _certificate2Collection;

        public StateCurrentCertificate()
        {
        }

        public StateCurrentCertificate(X509Certificate2Collection certificates)
        {
            var collection = new X509Certificate2Collection();
            collection.AddRange(certificates);
            _certificate2Collection = collection;
        }

        internal X509Certificate2Collection? GetCertificateCollection() => _certificate2Collection;

        internal void DisposeCoolDown()
        {
            if (_certificate2Collection is null) { return; }
            var collection = _certificate2Collection;
            _certificate2Collection = null;
            collection.DisposeCertificates(null);
            collection.Clear();
        }
    }
}
