using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http.Features;
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
/// TODO: Validate this with a performance test.
/// </remarks>
internal sealed partial class CertificateManagerPeriodicalRefresh
    : ICertificateManager
    , ICertificateManagerInternal
    , IDisposable
{
    // added + and may be loaded
    private readonly ConcurrentDictionary<CertificateRequest, CertificateRequest> _registeredNormalizedByRequest = new();

    private readonly ConcurrentDictionary<CertificateRequest, StateCurrentCertificate> _currentlyLoadedByRequestNormalized = new();

    // loaded - to be used while Refresh only
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _refreshLoadedByRequest = new();

    // loaded at least one generation before
    private readonly ConcurrentDictionary<CertificateRequest, StateLoadedCertificate> _previousByRequest = new();

    // level of generations of unused - the higher the number the lesser used
    private readonly ConcurrentDictionary<CertificateRequest, int> _ghostGenerationByRequestNormalized = new();

    private readonly ConcurrentDictionary<string, CertificateRequestCollection> _currentByRequestCollection = new();

    private readonly ConcurrentDictionary<string, Timestamped<X509Certificate2Collection>> _cacheByRequestCollection = new();

    private IDisposable? _unwireOptionsOnChange;
    private int _generationsUntilSleep = 10;
    private string? _certificateRootPath;
    private ICertificateFileLoader _certificateFileLoader;
    private readonly CertificateManagerFileWatcher _certificateManagerFileWatcher;
    private readonly StateReload _stateReload;
    private readonly ICertificateStoreLoader _certificateStoreLoader;
    private readonly ILogger<CertificateManagerPeriodicalRefresh> _logger;

    // when is their a need to reload - base on NotBefore and NotAfter
    private StateLoadingDateTime _refreshLoadingDateTime = new();

    private System.Threading.Timer? _timerRefresh;
    private TimeSpan _refreshInterval = TimeSpan.FromMinutes(10);
    private bool _lockLoading;

    // caching delegates
    private readonly Action<FileChanged> _onFileChanged;
    private readonly Func<X509Certificate2, List<CertificateRequest>, bool> _onCheckLoadedStoreCertificate;

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
        _logger = logger;
        _onFileChanged = OnFileChanged;
        _onCheckLoadedStoreCertificate = CheckLoadedStoreCertificate;
    }

    public CertificateManagerPeriodicalRefresh(
        IOptionsMonitor<CertificateManagerOptions> options,
        ICertificateStoreLoader certificateStoreLoader,
        ICertificateFileLoader certificateFileLoader,
        ILogger<CertificateManagerFileWatcher> loggerCertificateManagerFileWatcher,
        ILogger<CertificateManagerPeriodicalRefresh> logger
        )
    {
        _stateReload = new StateReload(this);
        _certificateManagerFileWatcher = new CertificateManagerFileWatcher(loggerCertificateManagerFileWatcher);
        _certificateStoreLoader = certificateStoreLoader;
        _certificateFileLoader = certificateFileLoader;
        _logger = logger;
        _onFileChanged = OnFileChanged;
        _onCheckLoadedStoreCertificate = CheckLoadedStoreCertificate;

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

    public IDisposable AddRequestCollection(CertificateRequestCollection requestCollection)
    {
        // ensure AddRequest is called
        lock (_currentByRequestCollection)
        {
            for (var index = 0; index < requestCollection.CertificateRequests.Count; index++)
            {
                var request = requestCollection.CertificateRequests[index];
                var requestNext = AddRequest(request);
                if (!request.Equals(requestNext))
                {
                    requestCollection.CertificateRequests[index] = requestNext;
                }
            }

            if (_currentByRequestCollection.TryGetValue(requestCollection.Id, out var current))
            {
                if (current == requestCollection)
                {
                    return new RemoveRequestCollectionDisposable(requestCollection, this);
                }
                else
                {
                    _currentByRequestCollection.TryUpdate(requestCollection.Id, requestCollection, current);
                    return new RemoveRequestCollectionDisposable(requestCollection, this);
                }
            }
            else
            {
                _currentByRequestCollection.TryAdd(requestCollection.Id, requestCollection);
                return new RemoveRequestCollectionDisposable(requestCollection, this);
            }
        }
    }

    public bool RemoveRequestCollection(CertificateRequestCollection requestCollection)
        => RemoveRequestCollection(requestCollection.Id);

    private bool RemoveRequestCollection(string requestCollectionId)
    {
        lock (_currentByRequestCollection)
        {
            if (_currentByRequestCollection.TryRemove(requestCollectionId, out var requestCollection))
            {
                var remainingCertificateRequests = new HashSet<CertificateRequest>();
                foreach (var (key, crc) in _currentByRequestCollection)
                {
                    foreach (var request in crc.CertificateRequests)
                    {
                        remainingCertificateRequests.Add(request);
                    }
                }
                foreach (var request in requestCollection.CertificateRequests)
                {
                    if (!remainingCertificateRequests.Contains(request))
                    {
                        RemoveRequest(request);
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    public CertificateRequest AddRequest(CertificateRequest request)
    {
        if (request.IsStoreCert() == request.IsFileCert())
        {
            throw new ArgumentException("The CertificateRequest must be either a store or a file certificate.", nameof(request));
        }

        if (_registeredNormalizedByRequest.TryGetValue(request, out var requestNormalized))
        {
            return requestNormalized;
        }

        requestNormalized = request;

        if (requestNormalized.FileRequest is { } fileRequest)
        {
            var (path, pathChanged) = GetFullPath(fileRequest.Path);
            var (keyPath, keyPathChanged) = GetFullPath(fileRequest.KeyPath);
            if (pathChanged || keyPathChanged)
            {
                requestNormalized = requestNormalized with
                {
                    FileRequest = fileRequest with
                    {
                        Path = path,
                        KeyPath = keyPath
                    }
                };
            }

            if (path is { Length: > 0 } fileRequestPath)
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
            if (keyPath is { Length: > 0 } fileRequestKeyPath)
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

        if (!_registeredNormalizedByRequest.ContainsKey(request))
        {
            if (!request.Requirement.HasValue || !request.Requirement.Value.AllowCertificateSelfSigned) {
                throw new Exception("HACK");
            }

            if (_registeredNormalizedByRequest.TryAdd(request, requestNormalized))
            {
                _=_registeredNormalizedByRequest.TryAdd(requestNormalized, requestNormalized);
                ResetGhostGenerationRequest(requestNormalized);

                lock (_stateReload)
                {
                    _stateReload.SetIsLoadNeeded();
                }
            }
        }

        return requestNormalized;
    }

    public bool RemoveRequest(CertificateRequest request)
    {
        if (_registeredNormalizedByRequest.TryGetValue(request, out var requestNormalized))
        {
            request = requestNormalized;
        }
        if (_currentlyLoadedByRequestNormalized.TryRemove(request, out var result))
        {
            result.Dispose();
            return true;
        }
        else
        {
            return false;
        }
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
        if (_registeredNormalizedByRequest.TryGetValue(request, out var requestNormalized))
        {
            request = requestNormalized;
        }
        // ensure the certificates are loaded
        {
            var refreshForce = IsAwakeNeeded(request);
            ResetGhostGenerationRequest(request);
            if (RefreshInternal(refreshForce, false))
            {
                StartRefresh();
            }
        }

        // get the certificates and return them
        _ = _currentlyLoadedByRequestNormalized.TryGetValue(request, out var state);
        var value = state?.GetSharedCertificateCollection();
        return SharedX509Certificate2CollectionByCertificateRequest.Create(value, request, this);
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="requestCollection"></param>
    /// <returns></returns>
    public ISharedValue<X509Certificate2Collection?> GetCertificateCollection(CertificateRequestCollection requestCollection)
    {
#if DEBUG
        foreach (var request in requestCollection.CertificateRequests)
        {
            if (request.IsFileCert()
                  && request.FileRequest is { } fileRequest
                  && fileRequest.Path is { Length: > 0 } fileRequestPath)
            {
                if (!System.IO.Path.IsPathFullyQualified(fileRequestPath))
                {
                    throw new ArgumentException($"fileRequest.Path:{fileRequestPath}", nameof(requestCollection));
                }
            }
        }
#endif
        var refresh = false;

        // lock the requestCollection, since a refresh may be needed otherwise it should be quickly finished.
        lock (requestCollection)
        {
            foreach (var request in requestCollection.CertificateRequests)
            {
                if (!_registeredNormalizedByRequest.TryGetValue(request, out var requestNormalized))
                {
                    requestNormalized = request;
                }
                // check if the certificate requested by this was not used in the near past
                if (!refresh && IsAwakeNeeded(requestNormalized))
                {
                    refresh = true;
                }
                ResetGhostGenerationRequest(requestNormalized);
            }

            RefreshInternal(refresh, false);

            // get the certificates, cache the result and return them
            {
                var timestamp = _stateReload.Changed;

                if (_cacheByRequestCollection.TryGetValue(requestCollection.Id, out var timestampedResult)
                    && timestampedResult.Timestamp == timestamp
                    )
                {
                    return SharedX509Certificate2CollectionByCertificateRequestCollection.Create(
                        timestampedResult.Value,
                        requestCollection,
                        this);
                }
                else
                {
                    // collect the certificates
                    var result = new X509Certificate2Collection();
                    foreach (var request in requestCollection.CertificateRequests)
                    {
                        if (!_registeredNormalizedByRequest.TryGetValue(request, out var requestNormalized))
                        {
                            requestNormalized = request;
                        }
                        if (_currentlyLoadedByRequestNormalized.TryGetValue(requestNormalized, out var state))
                        {
                            if (state.GetSharedCertificateCollection() is { } collection)
                            {
                                result.AddRange(collection);
                            }
                        }
                    }
                    if (requestCollection.X509Certificate2s is { } certs)
                    {
                        result.AddRange(certs);
                    }

                    // cache them
                    if (0 == result.Count && _logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug("No certificates found for requestCollection:{Id}", requestCollection.Id);
                    }
                    timestampedResult = new Timestamped<X509Certificate2Collection>(result, timestamp);
                    _cacheByRequestCollection[requestCollection.Id] = timestampedResult;

                    return SharedX509Certificate2CollectionByCertificateRequestCollection.Create(
                        result,
                        requestCollection,
                        this);
                }
            }
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

    private bool RefreshInternal(bool force, bool incrementGhostGeneration)
    {
        if (_lockLoading)
        {
            lock (_stateReload)
            {
                return RefreshInternal(force, incrementGhostGeneration);
            }
        }
        if (force || _stateReload.IsLoadNeeded())
        {
            lock (_stateReload)
            {
                if (force || _stateReload.IsLoadNeeded())
                {
                    try
                    {
                        _lockLoading = true;
                        var dtoLocalNow = TimeProvider.GetLocalNow();
                        var dtNow = dtoLocalNow.DateTime;
                        var nextEvent = dtNow.AddDays(1);
                        _refreshLoadingDateTime = new(dtNow, nextEvent);

                        if (incrementGhostGeneration)
                        {
                            IncrementGhostGenerationRequest();
                            _certificateManagerFileWatcher.Reset();
                        }
                        RefreshLoadStoreCertificates();
                        RefreshLoadFileCertificates();
                        RefreshPostLoadHandleChanges();
                        _stateReload.ResetIsLoadNeeded(_refreshLoadingDateTime);
                        _lockLoading = false;
                        return true;
                    }
                    catch (System.Exception error)
                    {
                        _logger.LogError(error, "Refresh failed");
                    }
                }
            }
        }
        return false;
    }

    private void ResetGhostGenerationRequest(CertificateRequest requestNormalized)
    {
        _ghostGenerationByRequestNormalized[requestNormalized] = 0;
    }

    private void IncrementGhostGenerationRequest()
    {
        foreach (var (request, requestNormalized) in _registeredNormalizedByRequest)
        {
            if (!request.Equals(requestNormalized))
            {
                continue;
            }
            if (_ghostGenerationByRequestNormalized.TryGetValue(requestNormalized, out var counter))
            {
                if (counter < _generationsUntilSleep)
                {
                    _ghostGenerationByRequestNormalized[requestNormalized] = counter + 1;
                }
            }
            else
            {
                _ghostGenerationByRequestNormalized[requestNormalized] = 2;
            }
        }
    }

    private bool IsAwakeNeeded(CertificateRequest requestNormalized)
    {
        if (_ghostGenerationByRequestNormalized.TryGetValue(requestNormalized, out var counter))
        {
            if (_generationsUntilSleep <= counter)
            {
                return true;
            }
            return false;
        }
        else
        {
            _ghostGenerationByRequestNormalized[requestNormalized] = _generationsUntilSleep;
            return true;
        }
    }

    private void StartRefresh()
    {
        if (_timerRefresh is null)
        {
            // one timer is enough
            return;
        }

        _timerRefresh = new System.Threading.Timer((_) =>
        {
            RefreshInternal(false, true);
        }, null, RefreshInterval, RefreshInterval);

        return;
    }

    private void RefreshLoadStoreCertificates()
    {
        Dictionary<CertificateStoreLocationName, List<CertificateRequest>> requestsByStoreLocationName = new();

        foreach (var (request, requestNormalized) in _registeredNormalizedByRequest)
        {
            if (!request.Equals(requestNormalized))
            {
                continue;
            }
            if (request.IsStoreCert() && request.StoreRequest is { StoreLocationName: { } storeLocationName })
            {
                // if the certificate requested by this was not used in the near past
                if (_ghostGenerationByRequestNormalized.TryGetValue(request, out var counter))
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
                    try
                    {
                        var notBefore = certificate.NotBefore;
                        var notAfter = certificate.NotAfter;
                        _ = _refreshLoadingDateTime.Add(notBefore).Add(notAfter);
                    }
                    catch (System.Security.Cryptography.CryptographicException)
                    {
                    }
                }
            }
        }

        // finally set the timestamp
        _stateReload.StoreLoaded = TimeProvider.GetUtcNow();
    }

    private bool CheckLoadedStoreCertificate(
        X509Certificate2 certificate,
        List<CertificateRequest> requests)
    {
        var hasMatched = false;

        foreach (var request in requests)
        {
            var requirement = CertificateRequirementUtility.CombineQ(CertificateRequirement, request.Requirement);
            var doesMatch = CertificateManagerUtility.DoesStoreCertificateMatchesRequest(
                request,
                requirement,
                certificate,
                ConfigureChainPolicy,
                TimeProvider,
                _logger);
            if (doesMatch)
            {
                hasMatched = true;
                if (!_refreshLoadedByRequest.TryGetValue(request, out var stateLoaded))
                {
                    stateLoaded = new StateLoadedCertificate(request);
                    _ = _refreshLoadedByRequest.TryAdd(request, stateLoaded);
                }
                stateLoaded.Add(certificate);
            }
        }
        if (!hasMatched)
        {
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("No matches for certificate:{Subject}", certificate.Subject);
            }
        }
        return hasMatched;
    }

    private void RefreshLoadFileCertificates()
    {
        var fromOptions = CertificateRequirement;

        foreach (var (request, requestNormalized) in _registeredNormalizedByRequest)
        {
            if (!request.Equals(requestNormalized))
            {
                continue;
            }
            // the certificate requested by this was not used in the near past.
            if (_ghostGenerationByRequestNormalized.TryGetValue(request, out var counter))
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
                        if (CheckLoadedFileCertificate(request, requirement, itemCertificate))
                        {
                            hasMatched = true;
                        }
                    }
                    if (hasMatched)
                    {
                        foreach (var itemCertificate in certificateCollection)
                        {
                            try
                            {
                                var notBefore = itemCertificate.NotBefore;
                                var notAfter = itemCertificate.NotAfter;
                                _ = _refreshLoadingDateTime.Add(notBefore).Add(notAfter);
                            }
                            catch (System.Security.Cryptography.CryptographicException)
                            {
                            }
                        }
                    }
                }
                //
                if (!hasMatched)
                {
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        if (certificateCollection is { })
                        {
                            foreach (var certificate in certificateCollection)
                            {
                                _logger.LogDebug("No matches for certificate:{Subject}", certificate.Subject);
                            }
                        }
                    }

                    // if no CertificateRequest is interested in this certificate - so dispose it
                    certificateCollection.DisposeCertificates(default);
                }
            }
        }

        // finally set the timestamp
        _stateReload.FileLoaded = TimeProvider.GetUtcNow();
    }

    private bool CheckLoadedFileCertificate(
        CertificateRequest request,
        CertificateRequirement requirement,
        X509Certificate2 certificate)
    {
        var doesMatch = CertificateManagerUtility.DoesFileCertificateMatchesRequest(
            request,
            requirement,
            certificate,
            ConfigureChainPolicy,
            TimeProvider,
            _logger);
        if (doesMatch)
        {
            if (!_refreshLoadedByRequest.TryGetValue(request, out var stateLoaded))
            {
                stateLoaded = new StateLoadedCertificate(request);
                _ = _refreshLoadedByRequest.TryAdd(request, stateLoaded);
            }
            stateLoaded.Add(certificate);
            return true;
        }
        return false;
    }

    private void RefreshPostLoadHandleChanges()
    {
        var changed = false;
        var loaded = _stateReload.Loaded;
        foreach (var request in _refreshLoadedByRequest.Keys)
        {
            if (_refreshLoadedByRequest.TryRemove(request, out var stateLoaded))
            {
                if (RefreshPostLoadHandleChangesForOne(request, stateLoaded))
                {
                    changed = true;
                }
            }
        }
        if (changed)
        {
            var timestamp = _stateReload.Changed = _stateReload.Loaded;
            foreach (var (key, timestampedCollection) in _cacheByRequestCollection)
            {
                if (timestampedCollection.Timestamp < timestamp)
                {
                    _ = _cacheByRequestCollection.TryRemove(key, out var _);
                }
            }
        }
    }

    private bool RefreshPostLoadHandleChangesForOne(CertificateRequest request, StateLoadedCertificate stateLoaded)
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
                _ = _refreshLoadedByRequest.TryRemove(request, out _);
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
        if (_currentlyLoadedByRequestNormalized.TryGetValue(request, out var oldStateCurrent))
        {
            _currentlyLoadedByRequestNormalized[request] = stateCurrent;
            oldStateCurrent.Dispose();
        }
        else
        {
            _currentlyLoadedByRequestNormalized[request] = stateCurrent;
        }
        return true;
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

    private sealed class RemoveRequestCollectionDisposable : IDisposable
    {
        private CertificateRequestCollection? _requestCollection;
        private CertificateManagerPeriodicalRefresh? _certificateManager;

        internal RemoveRequestCollectionDisposable(
            CertificateRequestCollection requestCollection,
            CertificateManagerPeriodicalRefresh certificateManager
            )
        {
            _requestCollection = requestCollection;
            _certificateManager = certificateManager;
        }

        public void Dispose()
        {
            if (_requestCollection is { } requestCollection
                && _certificateManager is { } certificateManager
                )
            {
                _requestCollection = null;
                _certificateManager = null;

                certificateManager.RemoveRequestCollection(requestCollection);
            }
        }
    }

    private sealed class StateReload(CertificateManagerPeriodicalRefresh certificateManager)
    {
        private readonly CertificateManagerPeriodicalRefresh _certificateManager = certificateManager;
        private bool _isLoadNeededNow;
        private DateTimeOffset? _isLoadNeedRefreshTime;
        private DateTimeOffset _storeLoaded;
        private DateTimeOffset _fileLoaded;
        private StateLoadingDateTime _stateCurrentLoadingDateTime = new StateLoadingDateTime();

        internal DateTimeOffset StoreLoaded { get => _storeLoaded; set { _storeLoaded = Loaded = value; } }
        internal DateTimeOffset FileLoaded { get => _fileLoaded; set { _fileLoaded = Loaded = value; } }

        internal DateTimeOffset Loaded { get; set; }

        internal DateTimeOffset Changed { get; set; }

        public DateTimeOffset GetUtcNow() => _certificateManager.TimeProvider.GetUtcNow();

        internal void SetIsLoadNeeded()
        {
            if (_isLoadNeededNow) { return; }
            _isLoadNeededNow = true;
        }

        internal void ResetIsLoadNeeded(StateLoadingDateTime stateLoadingDateTime)
        {
            _isLoadNeededNow = false;
            _stateCurrentLoadingDateTime = stateLoadingDateTime;
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

            if (_stateCurrentLoadingDateTime.IsLoadNeeded(now.DateTime))
            {
                _isLoadNeededNow = true;
                return true;
            }

            return false;
        }
    }

    private sealed class StateLoadingDateTime
    {
        private readonly DateTime _now;
        internal DateTime NextEvent;

        internal StateLoadingDateTime()
            : this(DateTime.MinValue, DateTime.MaxValue) { }

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

    private sealed class StateLoadedCertificate
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

    private sealed class StateCurrentCertificate
    {
        private bool _disposeIfPossible;
        private int _referenceCounter;
        private X509Certificate2Collection? _certificate2Collection;

        internal StateCurrentCertificate(X509Certificate2Collection certificates)
        {
            var sortedCertificates = certificates
                .Select((certificate) => (notBefore: certificate.GetNotBeforeOrDefault(DateTime.MaxValue), certificate: certificate))
                .OrderBy(certificate => certificate.notBefore);
            var collection = new X509Certificate2Collection();
            foreach (var item in sortedCertificates)
            {
                collection.Add(item.certificate);
            }
            _certificate2Collection = collection;
        }

        internal X509Certificate2Collection GetCertificateCollection() => _certificate2Collection ?? throw new ObjectDisposedException("StateCurrentCertificate");

        internal X509Certificate2Collection GetSharedCertificateCollection()
        {
            var result = _certificate2Collection ?? throw new ObjectDisposedException("StateCurrentCertificate");
            System.Threading.Interlocked.Increment(ref _referenceCounter);
            return result;
        }

        internal void DecrementReferenceCounter()
        {
            if (0 == System.Threading.Interlocked.Decrement(ref _referenceCounter))
            {
                if (_disposeIfPossible)
                {
                    Dispose();
                }
            }
        }

        internal bool IsDisposePrevented { get; set; }

        internal bool Dispose()
        {
            // already disposed?
            if (_certificate2Collection is null)
            {
                return true;
            }
            // PreventDispose==true means that this was GivenAway and it is not this to dispose.
            if (IsDisposePrevented)
            {
                return true;
            }

            // Still in use so, do not dispose
            if (0 < _referenceCounter)
            {
                _disposeIfPossible = true;
                return false;
            }

            var collection = _certificate2Collection;
#warning TODO: Dispose the certificates
            /*
            foreach (var certificate in collection) {
                certificate.Thumbprint
            }
            */
            _certificate2Collection = null;
            collection.DisposeCertificates(null);
            collection.Clear();
            return true;
        }
    }

    private sealed class SharedX509Certificate2CollectionByCertificateRequestCollection : ISharedValue<X509Certificate2Collection?>
    {
        internal static ISharedValue<X509Certificate2Collection?> Create(
            X509Certificate2Collection? value,
            CertificateRequestCollection certificateRequestCollection,
            CertificateManagerPeriodicalRefresh certificateManager
            )
        {
            if (value is null)
            {
                var result = new SharedX509Certificate2CollectionByCertificateRequestCollection(null, null, null);
                System.GC.SuppressFinalize(result);
                return result;
            }
            else
            {
                var result = new SharedX509Certificate2CollectionByCertificateRequestCollection(
                    value,
                    certificateRequestCollection,
                    certificateManager);
                return result;
            }
        }

        private CertificateRequestCollection? _certificateRequestCollection;
        private CertificateManagerPeriodicalRefresh? _certificateManager;

        private SharedX509Certificate2CollectionByCertificateRequestCollection(
            X509Certificate2Collection? value,
            CertificateRequestCollection? certificateRequestCollection,
            CertificateManagerPeriodicalRefresh? certificateManager
            )
        {
            Value = value;
            _certificateRequestCollection = certificateRequestCollection;
            _certificateManager = certificateManager;
        }

        public X509Certificate2Collection? Value { get; private set; }

        public X509Certificate2Collection? GiveAway()
        {
            var value = Value;
            if (_certificateRequestCollection is { } certificateRequestCollection
                && _certificateManager is { } certificateManager
                )
            {
                _certificateRequestCollection = null;
                _certificateManager = null;
                foreach (var request in certificateRequestCollection.CertificateRequests)
                {
                    if (certificateManager._currentlyLoadedByRequestNormalized.TryGetValue(request, out var state))
                    {
                        state.IsDisposePrevented = true;
                    }
                }
            }
            return value;
        }

        private void Dispose(bool disposing)
        {
            if (_certificateRequestCollection is { } certificateRequestCollection
                && _certificateManager is { } certificateManager
                )
            {
                if (disposing)
                {
                    Value = null;
                    _certificateRequestCollection = null;
                    _certificateManager = null;
                }

                foreach (var request in certificateRequestCollection.CertificateRequests)
                {
                    if (!certificateManager._registeredNormalizedByRequest.TryGetValue(request, out var requestNormalized))
                    {
                        requestNormalized = request;
                    }
                    if (certificateManager._currentlyLoadedByRequestNormalized.TryGetValue(requestNormalized, out var state))
                    {
                        state.DecrementReferenceCounter();
                    }
                }
            }
        }

        ~SharedX509Certificate2CollectionByCertificateRequestCollection()
        {
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    private sealed class SharedX509Certificate2CollectionByCertificateRequest : ISharedValue<X509Certificate2Collection?>
    {
        internal static ISharedValue<X509Certificate2Collection?> Create(
            X509Certificate2Collection? value,
            CertificateRequest certificateRequest,
            CertificateManagerPeriodicalRefresh certificateManager
            )
        {
            if (value is null)
            {
                var result = new SharedX509Certificate2CollectionByCertificateRequest(null, null, null);
                System.GC.SuppressFinalize(result);
                return result;
            }
            else
            {
                var result = new SharedX509Certificate2CollectionByCertificateRequest(
                    value,
                    certificateRequest,
                    certificateManager);
                return result;
            }
        }

        private CertificateRequest? _certificateRequest;
        private CertificateManagerPeriodicalRefresh? _certificateManager;

        private SharedX509Certificate2CollectionByCertificateRequest(
            X509Certificate2Collection? value,
            CertificateRequest? certificateRequest,
            CertificateManagerPeriodicalRefresh? certificateManager
            )
        {
            Value = value;
            _certificateRequest = certificateRequest;
            _certificateManager = certificateManager;
        }

        public X509Certificate2Collection? Value { get; private set; }

        public X509Certificate2Collection? GiveAway()
        {
            var value = Value;
            if (_certificateRequest is { } certificateRequest
                && _certificateManager is { } certificateManager
                )
            {
                _certificateRequest = null;
                _certificateManager = null;
                if (certificateManager._currentlyLoadedByRequestNormalized.TryGetValue(certificateRequest, out var state))
                {
                    state.IsDisposePrevented = true;
                }

            }
            return value;
        }

        private void Dispose(bool disposing)
        {
            if (_certificateRequest is { } certificateRequest
                && _certificateManager is { } certificateManager
                )
            {
                if (disposing)
                {
                    Value = null;
                    _certificateRequest = null;
                    _certificateManager = null;
                }

                if (certificateManager._currentlyLoadedByRequestNormalized.TryGetValue(certificateRequest, out var state))
                {
                    state.DecrementReferenceCounter();
                }
            }
        }

        ~SharedX509Certificate2CollectionByCertificateRequest()
        {
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
