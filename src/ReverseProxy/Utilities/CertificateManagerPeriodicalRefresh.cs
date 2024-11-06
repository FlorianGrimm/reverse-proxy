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
/// <remarks>
/// The assumption is that the certificates does not change very often.
/// TODO: How many certificates does a server have? ClientCertificates, JWT Token, not ServerCertificates these are handled by the kerstel itself.
/// TODO: Filewatcher for file certificates - revisit <see cref="Refresh(bool)"/>.
/// TODO: Validate this with a performance test.
/// TODO: NotBefore and NotAfter must be respected.
/// </remarks>
internal partial class CertificateManagerPeriodicalRefresh
    : ICertificateManager
    , IDisposable
{
    private readonly ConcurrentDictionary<string, Timestamped<X509Certificate2Collection>> _previousRequestCollection = new();
    private readonly ConcurrentDictionary<string, CertificateRequestCollection> _currentRequestCollection = new();

    // added
    private readonly ConcurrentDictionary<CertificateRequest, StateCurrentCertificate> _registeredByRequest = new();

    // loaded = added - ghosted
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _loadedByRequest = new();

    // loaded at least one generation before
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _previousByRequest = new();

    // level of generations of unused - the higher the number the lesser used
    private readonly ConcurrentDictionary<CertificateRequest, int> _ghostGenerationRequest = new();

    // the old certificates that will be disposed
    private readonly ConcurrentDictionary<X509Certificate2Collection, StateCurrentCertificate> _cooldownByRequest = new();

    private IDisposable? _unwireOptionsOnChange;
    private int _generationsUntilSleep = 10;
    private string? _certificateRootPath;
    private ICertificateFileLoader _certificateFileLoader;
    private readonly CertificateManagerFileWatcher _certificateManagerFileWatcher;
    private readonly StateReload _stateReload;
    private readonly ICertificateStoreLoader _certificateStoreLoader;
    private readonly ILogger<CertificateManagerPeriodicalRefresh> _logger;

    // when is their a need to reload - base on NotBefore and NotAfter 
    private StateLoadingDateTime _stateLoadingDateTime;

    private System.Threading.Timer? _timerRefresh;
    private TimeSpan _refreshInterval = TimeSpan.FromMinutes(10);

    private readonly Action<FileChanged> _onFileChanged;
    private readonly Func<X509Certificate2, List<CertificateRequest>, bool> _onCheckLoadedStoreCertificate;
    private readonly Action<X509Certificate2Collection?, CertificateRequest> _getCertificateRequestOnGiveAway;
    private readonly Action<X509Certificate2Collection?, CertificateRequestCollection> _getCertificateRequestCollectionOnGiveAway;

    public TimeSpan RefreshInterval
    {
        get => _refreshInterval;
        set
        {
            if (value < TimeSpan.FromMinutes(1)) { value = TimeSpan.FromMinutes(1); }
            _refreshInterval = value;
            _timerRefresh?.Change(value, value);
        }
    }
    public TimeSpan CoolDownTime { get; set; } = TimeSpan.FromMinutes(1);

    public CertificateRequirement CertificateRequirement { get; set; } = new();

    public Action<X509ChainPolicy>? ConfigureChainPolicy { get; set; }

    public int GenerationsUntilSleep { get => _generationsUntilSleep; set => _generationsUntilSleep = value > 3 ? value : 3; }

    public string? CertificateRootPath
    {
        get => _certificateRootPath;
        set
        {
            _certificateRootPath = value;
            if (CertificateFileLoader is { } certificateFileLoader)
            {
                certificateFileLoader.CertificateRootPath = value;
            }
        }
    }

    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;

    // TODO
    public ICertificateFileLoader CertificateFileLoader
    {
        get
        {
            return _certificateFileLoader;
        }

        set
        {
            _certificateFileLoader = value;
            if (_certificateFileLoader is { } certificateFileLoader)
            {
                certificateFileLoader.CertificateRootPath = CertificateRootPath;
            }
        }
    }

    public CertificateManagerPeriodicalRefresh(
        ICertificateStoreLoader certificateStoreLoader,
        ICertificateFileLoader certificateFileLoader,
        ILogger<CertificateManagerPeriodicalRefresh> logger)
    {
        _stateReload = new StateReload(this);
        _certificateManagerFileWatcher = new CertificateManagerFileWatcher(logger);
        _certificateStoreLoader = certificateStoreLoader;
        _certificateFileLoader = certificateFileLoader;
        certificateFileLoader.CertificateManagerFileWatcher = _certificateManagerFileWatcher;
        _logger = logger;
        _onFileChanged = OnFileChanged;
        _onCheckLoadedStoreCertificate = CheckLoadedStoreCertificate;
        _getCertificateRequestOnGiveAway = HandleCertificateRequestOnGiveAway;
        _getCertificateRequestCollectionOnGiveAway = HandleCertificateRequestCollectionOnGiveAway;

        _stateLoadingDateTime = new(DateTime.MinValue, DateTime.MaxValue);
    }

    public CertificateManagerPeriodicalRefresh(
        IOptionsMonitor<CertificateManagerOptions> options,
        ICertificateStoreLoader certificateStoreLoader,
        ICertificateFileLoader certificateFileLoader,
        ILogger<CertificateManagerPeriodicalRefresh> logger
        )
    {
        _stateReload = new StateReload(this);
        _certificateManagerFileWatcher = new CertificateManagerFileWatcher(logger);
        _certificateStoreLoader = certificateStoreLoader;
        _certificateFileLoader = certificateFileLoader;
        certificateFileLoader.CertificateManagerFileWatcher = _certificateManagerFileWatcher;
        _logger = logger;
        _onFileChanged = OnFileChanged;
        _onCheckLoadedStoreCertificate = CheckLoadedStoreCertificate;
        _getCertificateRequestOnGiveAway = HandleCertificateRequestOnGiveAway;
        _getCertificateRequestCollectionOnGiveAway = HandleCertificateRequestCollectionOnGiveAway;
        _stateLoadingDateTime = new(DateTime.MinValue, DateTime.MaxValue);

        OnOptionsChanged(options.CurrentValue, null);
        _unwireOptionsOnChange = options.OnChange(OnOptionsChanged);
    }

    private void OnOptionsChanged(CertificateManagerOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }

        var setIsLoadNeeded = false;
        RefreshInterval = options.RefreshInterval;
        CoolDownTime = options.CoolDownTime;
        var certificateRootPath = options.CertificateRootPath;
        if (string.IsNullOrEmpty(CertificateRootPath) && string.IsNullOrEmpty(certificateRootPath))
        {
            certificateRootPath = ".";
        }
        if (!string.Equals(CertificateRootPath, certificateRootPath, StringComparison.CurrentCultureIgnoreCase))
        {
            CertificateRootPath = certificateRootPath;
            setIsLoadNeeded = true;
        }
        if (!CertificateRequirement.Equals(options.CertificateRequirement))
        {
            CertificateRequirement = options.CertificateRequirement;
            setIsLoadNeeded = true;
        }
        if (!ReferenceEquals(ConfigureChainPolicy, options.ConfigureChainPolicy))
        {
            ConfigureChainPolicy = options.ConfigureChainPolicy;
            setIsLoadNeeded = true;
        }
        if (setIsLoadNeeded)
        {
            lock (_stateReload)
            {
                _stateReload.SetIsLoadNeeded();
            }
        }
    }

    public void AddRequestCollection(CertificateRequestCollection result)
    {
        if (_currentRequestCollection.TryGetValue(result.Id, out var current))
        {
            if (current != result)
            {
                _currentRequestCollection.TryUpdate(result.Id, result, current);
            }
            else
            {
                return;
            }
        }
        else
        {
            _currentRequestCollection.TryAdd(result.Id, result);
        }

        for (var index = 0; index < result.CertificateRequests.Count; index++)
        {
            var request = result.CertificateRequests[index];
            var requestNext = AddRequest(request);
            if (!request.Equals(requestNext))
            {
                result.CertificateRequests[index] = request;
            }
        }
    }

    public CertificateRequest AddRequest(CertificateRequest request)
    {
        if (!request.IsStoreCert() || !request.IsFileCert())
        {
            throw new ArgumentException("The CertificateRequest must be a store or a file certificate.", nameof(request));
        }

        if (request.FileRequest is { } fileRequest)
        {
            var (path, pathChanged) = GetFullPath(fileRequest.Path);
            var (keyPath, keyPathChanged) = GetFullPath(fileRequest.KeyPath);
            if (pathChanged || keyPathChanged)
            {
                request = request with
                {
                    FileRequest = fileRequest with
                    {
                        Path = path,
                        KeyPath = keyPath
                    }
                };
            }

            if (fileRequest.Path is { Length: > 0 } fileRequestPath)
            {
                if (_certificateManagerFileWatcher.AddWatch(
                    new FileWatcherRequest(
                        $"{request.Id}/Path",
                        fileRequestPath)
                    ) is { } fileChanged)
                {
                    fileChanged.OnHasChanged = _onFileChanged;
                }
            }
            if (fileRequest.KeyPath is { Length: > 0 } fileRequestKeyPath)
            {
                if (_certificateManagerFileWatcher.AddWatch(
                    new FileWatcherRequest(
                        $"{request.Id}/KeyPath",
                        fileRequestKeyPath)
                    ) is { } fileChanged)
                {
                    fileChanged.OnHasChanged = _onFileChanged;
                }
            }
        }

        if (!_registeredByRequest.ContainsKey(request))
        {
            if (_registeredByRequest.TryAdd(request, new StateCurrentCertificate()))
            {
                ResetGhostGenerationRequest(request);

                lock (_stateReload)
                {
                    _stateReload.SetIsLoadNeeded();
                }
            }
        }

        return request;
    }

    private void OnFileChanged(FileChanged changed)
    {
        _stateReload.SetIsLoadNeeded();
        changed.HasChanged = false;
    }

    private (string? result, bool changed) GetFullPath(string? filePathQ)
    {
        if (filePathQ is { Length: > 0 } filePath)
        {
            if (System.IO.Path.IsPathFullyQualified(filePath))
            {
                return (filePath, false);
            }

            if (CertificateRootPath is { Length: > 0 } certificateRootPath)
            {
                var fullPath = System.IO.Path.Combine(certificateRootPath, filePathQ);
                return (result: fullPath, changed: true);
            }
        }
        return (result: filePathQ, changed: false);
    }

    /// <summary>
    /// Get the certificate(s) for the CertificateRequest.
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequest request)
    {
        var result = GetCertificateCollectionInternal(request);
        return new SharedValue<X509Certificate2Collection?, CertificateRequest>(
            result,
            request,
            null,
            _getCertificateRequestOnGiveAway
            );
    }

    private void HandleCertificateRequestOnGiveAway(X509Certificate2Collection? value, CertificateRequest request)
    {
        if (_registeredByRequest.TryGetValue(request, out var stateCurrentCertificate))
        {
            stateCurrentCertificate.PreventDispose = true;
        }
    }

    private void HandleCertificateRequestCollectionOnGiveAway(X509Certificate2Collection? value, CertificateRequestCollection certificateRequestCollection)
    {
        foreach (var request in certificateRequestCollection.CertificateRequests)
        {
            if (_registeredByRequest.TryGetValue(request, out var stateCurrentCertificate))
            {
                stateCurrentCertificate.PreventDispose = true;
            }
        }
    }

    internal X509Certificate2Collection? GetCertificateCollectionInternal(CertificateRequest request)
    {
        // ensure the certificates are loaded
        {
            if (IsAwakeNeeded(request))
            {
                ResetGhostGenerationRequest(request);
                if (RefreshInternal(true, false))
                {
                    StartRefresh();
                }
            }
            else
            {
                ResetGhostGenerationRequest(request);
                if (RefreshInternal(false, false))
                {
                    StartRefresh();
                }
            }
        }

        // get the certificates and return them
        {
            if (_registeredByRequest.TryGetValue(request, out var state))
            {
                return state.GetCertificateCollection();
            }
        }

        // or return null
        return null;
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestCollection"></param>
    /// <returns></returns>
    public ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequestCollection requestCollection)
    {
        if (requestCollection.CertificateRequests.Count == 0)
        {
            return new SharedValue<X509Certificate2Collection?, CertificateRequestCollection>(
                requestCollection.X509Certificate2s, requestCollection, null, null);
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
                            ResetGhostGenerationRequest(request);
                        }
                    }
                    if (refresh)
                    {
                        _stateReload.SetIsLoadNeeded();
                    }
                    else
                    {
                        return new SharedValue<X509Certificate2Collection?, CertificateRequestCollection>(
                            timestampedResult.Value,
                            requestCollection,
                            null,
                            _getCertificateRequestCollectionOnGiveAway
                            );
                    }
                }
            }

            foreach (var request in requestCollection.CertificateRequests)
            {
                if (IsAwakeNeeded(request))
                {
                    refresh = true;
                }
                ResetGhostGenerationRequest(request);
            }
            if (refresh)
            {
                RefreshInternal(true, false);
            }

            // collect the certificates
            var result = new X509Certificate2Collection();
            var timestamp = _stateReload.Changed;
            foreach (var request in requestCollection.CertificateRequests)
            {
                if (GetCertificateCollectionInternal(request) is { } collection)
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
            return new SharedValue<X509Certificate2Collection?, CertificateRequestCollection>(
                result,
                requestCollection,
                null,
                _getCertificateRequestCollectionOnGiveAway);
        }
    }

    /// <summary>
    /// Refresh(reload) the certificates.
    /// </summary>
    /// <param name="force">false - only if needed; true - always</param>
    public void Refresh(bool force)
    {
        if (RefreshInternal(force, true))
        {
            StartRefresh();
        }
    }

    internal bool RefreshInternal(bool force, bool incrementGhostGeneration)
    {
        if (force || _stateReload.IsLoadNeeded())
        {
            lock (_stateReload)
            {
                try
                {
                    var dtoLocalNow = TimeProvider.GetLocalNow();
                    var dtNow = dtoLocalNow.DateTime;
                    var nextEvent = dtNow.AddDays(1);
                    _stateLoadingDateTime = new(dtNow, nextEvent);

                    if (incrementGhostGeneration)
                    {
                        IncrementGhostGenerationRequest();
                        _certificateManagerFileWatcher.Reset();
                    }
                    LoadStoreCertificates();
                    LoadFileCertificates();
                    PostLoadHandleChanges();
                    _stateReload.ResetIsLoadNeeded(_stateLoadingDateTime);

                    return true;
                }
                catch (System.Exception error)
                {
                    _logger.LogError(error, "Refresh failed");
                }
            }
        }
        return false;
    }

    private void ResetGhostGenerationRequest(CertificateRequest request)
    {
        _ghostGenerationRequest[request] = 0;
    }

    private void IncrementGhostGenerationRequest()
    {
        foreach (var request in _registeredByRequest.Keys.ToList())
        {
            if (_ghostGenerationRequest.TryGetValue(request, out var counter))
            {
                if (counter < _generationsUntilSleep)
                {
                    _ghostGenerationRequest[request] = counter + 1;
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
        if (_timerRefresh is null)
        {
            // one timer is engough
            return;
        }

        _timerRefresh = new System.Threading.Timer((_) =>
        {
            RefreshInternal(false, true);
        }, null, RefreshInterval, RefreshInterval);

        return;
    }

    private void LoadStoreCertificates()
    {
        Dictionary<CertificateStoreLocationName, List<CertificateRequest>> requestsByStoreLocationName = new();

        foreach (var request in _registeredByRequest.Keys)
        {
            if (request.IsStoreCert() && request.StoreRequest is { StoreLocationName: { } storeLocationName })
            {
                // if the certificate requested by this was not used in the near past
                if (_ghostGenerationRequest.TryGetValue(request, out var counter))
                {
                    if (_generationsUntilSleep <= counter)
                    {
                        // then skip this
                        continue;
                    }
                }

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
                var listCertificate = _certificateStoreLoader.Load(storeLocationName, requests, _onCheckLoadedStoreCertificate);
                foreach (var certificate in listCertificate)
                {
                    _ = _stateLoadingDateTime.Add(certificate.NotBefore).Add(certificate.NotAfter);
                }
            }
        }

        // finally set the timestamp
        _stateReload.StoreLoaded = TimeProvider.GetUtcNow();
    }

    private bool CheckLoadedStoreCertificate(X509Certificate2 certificate, List<CertificateRequest> requests)
    {
        var hasMatched = false;

        foreach (var request in requests)
        {
            if (CertificateManagerUtility.DoesStoreCertificateMatchesRequest(request, certificate, ConfigureChainPolicy, TimeProvider))
            {
                hasMatched = true;
                if (!_loadedByRequest.TryGetValue(request, out var stateLoaded))
                {
                    stateLoaded = new StateLoadedCertificate(request);
                    _ = _loadedByRequest.TryAdd(request, stateLoaded);
                }
                stateLoaded.Add(certificate);
            }
        }
        return hasMatched;
    }

    private void LoadFileCertificates()
    {
        var fromOptions = CertificateRequirement;

        foreach (var (request, stateCurrentCertificate) in _registeredByRequest.ToList())
        {
            // the certificate requested by this was not used in the near past.
            if (_ghostGenerationRequest.TryGetValue(request, out var counter))
            {
                if (_generationsUntilSleep <= counter)
                {
                    continue;
                }
            }

            if (request.FileRequest is { } fileRequest
                && request.FileRequest?.Path is { } filename)
            {
                var requirement = CertificateRequirementUtility.CombineQ(fromOptions, request.Requirement);
                var certificateCollection = CertificateFileLoader.LoadCertificateFromFile(request, fileRequest, requirement);

                // check which CertificateRequest is interested in this certificate
                var hasMatched = false;
                if (certificateCollection is { })
                {
                    foreach (var itemCertificate in certificateCollection)
                    {
                        if (CheckLoadedFileCertificate(request, itemCertificate))
                        {
                            hasMatched = true;
                        }
                    }
                    if (hasMatched)
                    {
                        foreach (var itemCertificate in certificateCollection)
                        {
                            _ = _stateLoadingDateTime.Add(itemCertificate.NotBefore).Add(itemCertificate.NotAfter);
                        }
                    }
                }
                if (!hasMatched)
                {
                    // if no CertificateRequest is interested in this certificate - so dispose it
                    certificateCollection.DisposeCertificates(default);
                }
            }
        }

        // finally set the timestamp
        _stateReload.FileLoaded = TimeProvider.GetUtcNow();
    }

    private bool CheckLoadedFileCertificate(CertificateRequest request, X509Certificate2 certificate)
    {
        if (CertificateManagerUtility.DoesFileCertificateMatchesRequest(request, certificate, ConfigureChainPolicy, TimeProvider))
        {
            if (!_loadedByRequest.TryGetValue(request, out var stateLoaded))
            {
                stateLoaded = new StateLoadedCertificate(request);
                _ = _loadedByRequest.TryAdd(request, stateLoaded);
            }
            stateLoaded.Add(certificate);
            return true;
        }
        return false;
    }

    private void PostLoadHandleChanges()
    {
        var changed = false;
        var loaded = _stateReload.Loaded;
        foreach (var request in _loadedByRequest.Keys)
        {
            if (_loadedByRequest.TryRemove(request, out var stateLoaded))
            {
                if (PostLoadHandleChangesForOne(request, stateLoaded))
                {
                    changed = true;
                }
            }
        }
        if (changed)
        {
            TriggerDisposePastNeeded();
            _stateReload.Changed = _stateReload.Loaded;
        }
    }

    private bool PostLoadHandleChangesForOne(CertificateRequest request, StateLoadedCertificate stateLoaded)
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
                _ = _loadedByRequest.TryRemove(request, out _);
                return false;
            }
            else
            {
                // if the certificate(s) are different
                _ = _previousByRequest.TryAdd(request, stateLoaded);
            }
        }
        else
        {
            // if the certificate(s) are new
            _ = _previousByRequest.TryAdd(request, stateLoaded);
        }

        // if the certificate(s) are new or different
        var stateCurrent = new StateCurrentCertificate(stateLoaded.Certificates);
        if (_registeredByRequest.TryGetValue(request, out var oldStateCurrent))
        {
            _registeredByRequest[request] = stateCurrent;
            var certificateCollection = oldStateCurrent.GetCertificateCollection();
            if (certificateCollection is not null)
            {
                _cooldownByRequest[certificateCollection] = oldStateCurrent;
            }
        }
        else
        {
            _registeredByRequest[request] = stateCurrent;
        }
        return true;
    }

    private void TriggerDisposePastNeeded()
    {
        var list = new List<StateCurrentCertificate>();
        foreach (var key in _cooldownByRequest.Keys)
        {
            if (_cooldownByRequest.TryRemove(key, out var stateCooldown))
            {
                list.Add(stateCooldown);
            }
        }
        if (0 == list.Count) { return; }

        var state = new StateDisposeCoolDown(list, CoolDownTime);
        state.Start();
    }

    public void Dispose()
    {
        // since this is a singleton this will be rearly called (in production).
        using (var timer = _timerRefresh)
        {
            using (var optionsOnChange = _unwireOptionsOnChange)
            {
                _unwireOptionsOnChange = null;
                _timerRefresh = null;
            }
        }
    }

    // TODO: is their a need for internal void RemoveRequest(CertificateRequest request) or is ghosting good enough?

    internal class StateReload
    {
        private readonly CertificateManagerPeriodicalRefresh _certificateManager;
        private bool _isLoadNeededNow;
        private DateTimeOffset? _isLoadNeedRefreshTime;
        private DateTimeOffset _storeLoaded;
        private DateTimeOffset _fileLoaded;
        private StateLoadingDateTime _stateLoadingDateTime = new StateLoadingDateTime(DateTime.MinValue, DateTime.MinValue);

        internal DateTimeOffset StoreLoaded { get => _storeLoaded; set { _storeLoaded = Loaded = value; } }
        internal DateTimeOffset FileLoaded { get => _fileLoaded; set { _fileLoaded = Loaded = value; } }

        internal DateTimeOffset Loaded { get; set; }

        internal DateTimeOffset Changed { get; set; }

        public StateReload(CertificateManagerPeriodicalRefresh certificateManager)
        {
            _certificateManager = certificateManager;
        }

        public DateTimeOffset GetUtcNow() => _certificateManager.TimeProvider.GetUtcNow();

        internal void SetIsLoadNeeded()
        {
            if (_isLoadNeededNow) { return; }
            _isLoadNeededNow = true;
        }

        internal void ResetIsLoadNeeded(StateLoadingDateTime stateLoadingDateTime)
        {
            _isLoadNeededNow = false;
            _stateLoadingDateTime = stateLoadingDateTime;
            _isLoadNeedRefreshTime = _certificateManager.TimeProvider.GetLocalNow()
                .Add(_certificateManager.RefreshInterval);
        }

        internal bool IsLoadNeeded()
        {
            if (_isLoadNeededNow) { return true; }

            var now = _certificateManager.TimeProvider.GetLocalNow();
            if (_isLoadNeedRefreshTime.HasValue
                && now < _isLoadNeedRefreshTime.Value)
            {
                _isLoadNeededNow = true;
                return true;
            }

            if (_stateLoadingDateTime.IsLoadNeeded(now.DateTime))
            {
                _isLoadNeededNow = true;
                return true;
            }

            return false;
        }
    }

    internal sealed class StateLoadingDateTime
    {
        private readonly DateTime _now;
#pragma warning disable IDE1006 // Naming Styles
        internal DateTime NextEvent;
#pragma warning restore IDE1006 // Naming Styles

        internal StateLoadingDateTime(DateTime now, DateTime nextEvent)
        {
            _now = now;
            NextEvent = nextEvent;
        }

        internal StateLoadingDateTime Add(DateTime dt)
        {
            if (_now < dt && dt < NextEvent)
            {
                NextEvent = dt;
            }
            return this;
        }

        internal bool IsLoadNeeded(DateTime now)
        {
            return (_now < now && NextEvent < now);
        }
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

        public bool PreventDispose { get; set; }

        internal void DisposeCoolDown()
        {
            // already disposed?
            if (_certificate2Collection is null)
            {
                return;
            }
            // PreventDispose==true means that this was GivenAway and it is not this to dispose.
            if (PreventDispose)
            {
                return;
            }
            var collection = _certificate2Collection;
            _certificate2Collection = null;
            collection.DisposeCertificates(null);
            collection.Clear();
        }
    }

    private sealed class StateDisposeCoolDown(
      List<StateCurrentCertificate> list,
      TimeSpan coolDownTime
      )
    {
        private List<StateCurrentCertificate>? _list = list;
        private readonly TimeSpan _coolDownTime = coolDownTime;
        private System.Threading.Timer? _timer;

        internal void Start()
        {
            _timer = new System.Threading.Timer(
                Execute,
                null,
                _coolDownTime,
                Timeout.InfiniteTimeSpan);
        }

        private void Execute(object? state)
        {
            using (var t = _timer)
            {
                _timer = null;
                if (_list is { } list)
                {
                    _list = null;
                    foreach (var item in list)
                    {
                        item.DisposeCoolDown();
                    }
                }
            }
        }
    }
}
