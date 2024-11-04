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
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _previousByRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _loadedByRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateCurrentCertificate> _currentByRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, int> _ghostGenerationRequest = new();
    private readonly ConcurrentDictionary<CertificateRequest, StateCurrentCertificate> _cooldownByRequest = new();
    private readonly ConcurrentDictionary<CertificateStoreLocationName, CertificateStoreLocationName> _certificateStoreLocationNames = new();
    private IDisposable? _unwireOptionsOnChange;
    private CancellationTokenSource? _ctsRefresh;
    private int _generationsUntilSleep = 10;
    private string? _certificateRootPath;
    private ICertificateFileLoader _certificateFileLoader;
    private readonly ICertificateManagerFileWatcher _certificateManagerFileWatcher;
    private readonly StateReload _stateReload;
    private readonly ICertificateStoreLoader _certificateStoreLoader;
    private readonly ILogger<CertificateManagerPeriodicalRefresh> _logger;

    private readonly Action<FileChanged> _onFileChanged;

    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan CoolDownTime { get; set; } = TimeSpan.FromMinutes(10);

    public int GenerationsUntilSleep { get => _generationsUntilSleep; set => _generationsUntilSleep = value > 3 ? value : 3; }

    public string? CertificateRootPath
    {
        get => _certificateRootPath;
        set
        {
            _certificateRootPath = value;
            if (CertificateFileLoader is { } loader)
            {
                loader.CertificateRootPath = value;
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
            if (_certificateFileLoader is { })
            {
                _certificateFileLoader.CertificateRootPath = CertificateRootPath;
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

        OnOptionsChanged(options.CurrentValue, null);
        _unwireOptionsOnChange = options.OnChange(OnOptionsChanged);
    }

    private void OnOptionsChanged(CertificateManagerOptions options, string? name)
    {
        if (!string.IsNullOrEmpty(name)) { return; }

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
            lock (_stateReload)
            {
                _stateReload.SetIsLoadNeeded();
            }
        }
    }

#if false
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
#endif

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

        if (!_currentByRequest.ContainsKey(request))
        {
            if (_currentByRequest.TryAdd(request, new StateCurrentCertificate()))
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
        _stateReload.SetIsLoadNeeded(true);
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
    public IShared<X509Certificate2Collection?> GetCertificateCollection(CertificateRequest request)
    {
        var result = GetCertificateCollectionInternal(request);
        return new Shared<X509Certificate2Collection?>(result);
    }

    internal X509Certificate2Collection? GetCertificateCollectionInternal(CertificateRequest request)
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
            ResetGhostGenerationRequest(request);

            if (_currentByRequest.TryGetValue(request, out var state))
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
    public IShared<X509Certificate2Collection?> GetCertificateCollection(CertificateRequestCollection requestCollection)
    {
        if (requestCollection.CertificateRequests.Count == 0)
        {
            return new Shared<X509Certificate2Collection?>(requestCollection.X509Certificate2s);
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
                        return new Shared<X509Certificate2Collection?>(timestampedResult.Value);
                    }
                }
            }

            // collect the certificates
            var result = new X509Certificate2Collection();
            var timestamp = _stateReload.Changed;
            foreach (var request in requestCollection.CertificateRequests)
            {
                ResetGhostGenerationRequest(request);

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
            return new Shared<X509Certificate2Collection?>(result);
        }
    }

    /// <summary>
    /// Refresh(reload) the certificates.
    /// </summary>
    /// <param name="force">false - only if needed; true - always</param>
    public void Refresh(bool force)
    {
        if (RefreshInternal(force))
        {
            StartRefresh();
        }
    }

    internal bool RefreshInternal(bool force)
    {
        if (force || _stateReload.IsLoadNeeded())
        {
            lock (_stateReload)
            {
                // TODO: review after the file watcher is implemented
                try
                {
                    IncrementGhostGenerationRequest();
                    LoadStoreCertificates();
                    LoadFileCertificates();
                    PostLoadHandleChanges();
                    _stateReload.SetIsLoadNeeded(false);
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
        // thinkof: is a timer the better solution?
        if (_ctsRefresh is { }) { return; }
        _ctsRefresh = new CancellationTokenSource();

        var ctStop = _ctsRefresh.Token;
        Task.Run(async () =>
        {
            while (ctStop.IsCancellationRequested)
            {
                await Task.Delay(RefreshInterval, ctStop);

                RefreshInternal(false);
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
            if (request.IsStoreCert() && request.StoreRequest is { StoreLocationName: { } storeLocationName })
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
                _certificateStoreLoader.Load(storeLocationName, (certificate) =>
                {
                    var isInterested = false;

                    foreach (var request in requests)
                    {
                        if (CertificateManagerUtility.DoesStoreCertificateMatchesRequest(request, certificate, TimeProvider))
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
                    return isInterested;
                });
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
            if (request.FileRequest?.Path is { } filePath)
            {
                if (!requestsByFilename.TryGetValue(filePath, out var requests))
                {
                    requests = new List<CertificateRequest>();
                    requestsByFilename.Add(filePath, requests);
                }
                requests.Add(request);
            }
        }

        // load from file
        {
            foreach (var (filename, requests) in requestsByFilename)
            {
                var (fileRequest, requirement) = CombineFileCertificateRequest(new(), requests);
                var certificateCollection = CertificateFileLoader.LoadCertificateFromFile(requests, fileRequest, requirement);

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
                    if (CertificateManagerUtility.DoesFileCertificateMatchesRequest(request, certificate, TimeProvider))
                    {
                        isInterested = true;
                        if (!_loadedByRequest.TryGetValue(request, out var stateLoaded))
                        {
                            stateLoaded = new StateLoadedCertificate(request);
                            _ = _loadedByRequest.TryAdd(request, stateLoaded);
                        }
                        stateLoaded.Add(certificate);
                    }
                }
            }
        }

        // finally set the timestamp
        _stateReload.FileLoaded = TimeProvider.GetUtcNow();
    }

    // for testing
    internal (
        CertificateFileRequest fileRequest,
        CertificateRequirement requirement
        ) CombineFileCertificateRequest(
        CertificateRequirement requirement,
        List<CertificateRequest> requests)
    {
        string? path = null;
        string? keyPath = null;
        string? password = null;
        foreach (var request in requests)
        {
            if (request.FileRequest is { } requestFileRequest)
            {
                if (requestFileRequest.Path is { Length: > 0 } requestPath)
                {
                    path = requestPath;
                }
                if (requestFileRequest.KeyPath is { Length: > 0 } requestKeyPath)
                {
                    keyPath = requestKeyPath;
                }
                if (requestFileRequest.Password is { Length: > 0 } requestPassword)
                {
                    password = requestPassword;
                }
            }
            requirement = CertificateRequirementUtility.CombineQ(requirement, request.Requirement);
        }

        return (new CertificateFileRequest(path, keyPath, password), requirement);
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
            _stateReload.TriggerIsDisposePastNeeded();
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

    // TODO: is their a need for internal void RemoveRequest(CertificateRequest request) or is ghosting good enough?

    internal class StateReload
    {
        private readonly CertificateManagerPeriodicalRefresh _certificateManager;
        private bool _isLoadNeededNow;
        private DateTimeOffset? _isLoadNeedRefreshTime;
        private DateTimeOffset? _isDisposePastNeeded;
        private DateTimeOffset _storeLoaded;
        private DateTimeOffset _fileLoaded;

        internal DateTimeOffset StoreLoaded { get => _storeLoaded; set { _storeLoaded = Loaded = value; } }
        internal DateTimeOffset FileLoaded { get => _fileLoaded; set { _fileLoaded = Loaded = value; } }

        internal DateTimeOffset Loaded;

        internal DateTimeOffset Changed;

        public StateReload(CertificateManagerPeriodicalRefresh certificateManager)
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
