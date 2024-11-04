using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.FileProviders.Physical;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Utilities;

public sealed record class FileWatcherRequest(
    string Id,
    string FullName);

public sealed class FileChanged(FileWatcherRequest fileWatcherRequest)
{
    private bool _hasChanged;

    public string Id { get; } = fileWatcherRequest.Id;

    public string FullName { get; } = fileWatcherRequest.FullName;

    public bool HasChanged
    {
        get => _hasChanged;
        set
        {
            _hasChanged = value;
            if (value && OnHasChanged is { }) { OnHasChanged(this); }
        }
    }

    public Action<FileChanged>? OnHasChanged { get; set; }
}

public interface ICertificateManagerFileWatcher
    : IDisposable
{
    /// <summary>
    /// Returns a token that will fire when any watched <see cref="FileWatcherRequest"/> is changed on disk.
    /// </summary>
    IChangeToken GetChangeToken();

    /// <summary>
    /// Start watching a certificate's file path for changes.
    /// </summary>
    /// <param name="fileWatcherRequest">the file path.</param>
    FileChanged? AddWatch(FileWatcherRequest fileWatcherRequest);

    /// <summary>
    /// Stop watching a certificate's file path for changes.
    /// </summary>
    /// <param name="fileWatcherRequest">the file path.</param>
    void RemoveWatch(FileWatcherRequest fileWatcherRequest);

    /// <summary>
    /// Remove all watches.
    /// </summary>
    void Reset();
}

internal class CertificateManagerFileWatcher
    : ICertificateManagerFileWatcher
    , IDisposable
{
    private readonly Func<string, IFileProvider?> _fileProviderFactory;
    private readonly ILogger _logger;

    private readonly object _metadataLock = new();

    /// <remarks>Acquire <see cref="_metadataLock"/> before accessing.</remarks>
    private readonly Dictionary<string, DirectoryWatchMetadata> _metadataForDirectory = new();
    /// <remarks>Acquire <see cref="_metadataLock"/> before accessing.</remarks>
    private readonly Dictionary<string, FileWatchMetadata> _metadataForFile = new();

    private ConfigurationReloadToken _reloadToken = new();

    private bool _disposed;

    public CertificateManagerFileWatcher(
        ILogger logger)
        : this(
            logger,
            null)
    { }

    private static IFileProvider? CreatePhysicalFileProvider(string directoryPath)
        => (Directory.Exists(directoryPath)
            ? new PhysicalFileProvider(directoryPath, ExclusionFilters.None)
            {
                // Force polling because it monitors both symlinks and their targets,
                // whereas the non-polling watcher only monitors the symlinks themselves
                UseActivePolling = true,
                UsePollingFileWatcher = true,
            }
            : null);

    internal CertificateManagerFileWatcher(
        ILogger logger,
        Func<string, IFileProvider?>? fileProviderFactory = null)
    {
        _logger = logger;
        _fileProviderFactory = fileProviderFactory ?? CreatePhysicalFileProvider;
    }

    /// <summary>
    /// Returns a token that will fire when any watched <see cref="FileWatcherRequest"/> is changed on disk.
    /// </summary>
    public IChangeToken GetChangeToken() => _reloadToken;

    public ConcurrentDictionary<string, DateTimeOffset> Changed { get; } = new();

    /// <summary>
    /// Remove all watches.
    /// </summary>
    public void Reset()
    {
        lock (_metadataLock)
        {
            foreach (var fileMetadata in _metadataForFile.Values)
            {
                fileMetadata.Dispose();
                fileMetadata.Requests.Clear();
            }
            _metadataForFile.Clear();

            foreach (var directoryWatchMetadata in _metadataForDirectory.Values)
            {
                directoryWatchMetadata.Dispose();
            }
            _metadataForDirectory.Clear();
        }
    }

    public FileChanged? AddWatch(FileWatcherRequest fileWatcherRequest)
    {
        lock (_metadataLock)
        {
            return AddWatchUnsynchronized(fileWatcherRequest);
        }
    }

    private FileChanged? AddWatchUnsynchronized(FileWatcherRequest fileWatcherRequest)
    {
        var fullName = fileWatcherRequest.FullName;
        if (string.IsNullOrEmpty(fullName))
        {
            throw new ArgumentException("FullName is required", nameof(fileWatcherRequest));
        }
        var dir = Path.GetDirectoryName(fullName)
            ?? throw new ArgumentException("GetDirectoryName(FullName) is required", nameof(fileWatcherRequest));

        if (!_metadataForDirectory.TryGetValue(dir, out var dirMetadata))
        {
            // If we wanted to detected deletions of this whole directory (which we don't since we ignore deletions),
            // we'd probably need to watch the whole directory hierarchy

            var fileProvider = _fileProviderFactory(dir);
            if (fileProvider is null)
            {
                Log.DirectoryDoesNotExist(_logger, dir, fullName);
                return default;
            }

            dirMetadata = new DirectoryWatchMetadata(fileProvider);
            _metadataForDirectory.Add(dir, dirMetadata);

            Log.CreatedDirectoryWatcher(_logger, dir);
        }

        if (!_metadataForFile.TryGetValue(fullName, out var fileMetadata))
        {
            // PhysicalFileProvider appears to be able to tolerate non-existent files, as long as the directory exists

            var disposable = ChangeToken.OnChange(
                () => dirMetadata.FileProvider.Watch(Path.GetFileName(fullName)),
tuple => tuple.Item1.OnChange(tuple.Item2),
                ValueTuple.Create(this, fullName));

            fileMetadata = new FileWatchMetadata(disposable);
            _metadataForFile.Add(fullName, fileMetadata);
            dirMetadata.FileWatchCount++;

            Log.CreatedFileWatcher(_logger, fullName);
        }

        if (fileMetadata.Requests.TryGetValue(fileWatcherRequest.Id, out var fileChanged))
        {
            Log.ReusedObserver(_logger, fullName);
            return fileChanged;
        }

        fileChanged = new FileChanged(fileWatcherRequest);
        fileMetadata.Requests.Add(fileWatcherRequest.Id, fileChanged);
        Log.AddedObserver(_logger, fullName);

        Log.ObserverCount(_logger, fullName, fileMetadata.Requests.Count);
        Log.FileCount(_logger, dir, dirMetadata.FileWatchCount);
        return fileChanged;
    }

    private void OnChange(string path)
    {
        // Block until any in-progress updates are complete
        lock (_metadataLock)
        {
            if (!_metadataForFile.TryGetValue(path, out var fileMetadata))
            {
                Log.UntrackedFileEvent(_logger, path);
                return;
            }

            // Existence implied by the fact that we're tracking the file
            var dirMetadata = _metadataForDirectory[Path.GetDirectoryName(path)!];

            // We ignore file changes that result in a file becoming unavailable.
            // For example, if we lose access to the network share the file is
            // stored on, we don't notify our listeners because no one wants
            // their endpoint/server to shutdown when that happens.
            // We also anticipate that a cert file might be renamed to cert.bak
            // before a new cert is introduced with the old name.

            var fileInfo = dirMetadata.FileProvider.GetFileInfo(Path.GetFileName(path));
            if (!fileInfo.Exists)
            {
                Log.EventWithoutFile(_logger, path);
                return;
            }
            var requests = fileMetadata.Requests;
            foreach (var request in requests.Values)
            {
                request.HasChanged = true;
            }

            Log.FlaggedObservers(_logger, path, requests.Count);
        }

        // AddWatch and RemoveWatch don't affect the token, so this doesn't need to be under the semaphore.
        // It does however need to be synchronized, since there could be multiple concurrent events.
        var previousToken = Interlocked.Exchange(ref _reloadToken, new ConfigurationReloadToken());
        previousToken.OnReload();
    }

    /// <summary>
    /// Stop watching a certificate's file path for changes.
    /// </summary>
    /// <param name="fileWatcherRequest">the config defines the file path.</param>
    public void RemoveWatch(FileWatcherRequest fileWatcherRequest)
    {
        lock (_metadataLock)
        {
            RemoveWatchUnsynchronized(fileWatcherRequest);
        }
    }

    private void RemoveWatchUnsynchronized(FileWatcherRequest fileWatcherRequest)
    {
        var path = fileWatcherRequest.FullName;
        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentException("Path is required", nameof(fileWatcherRequest));
        }
        var dir = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("GetDirectoryName(path) is required", nameof(fileWatcherRequest));

        if (!_metadataForFile.TryGetValue(path, out var fileMetadata))
        {
            Log.UnknownFile(_logger, path);
            return;
        }

        var requests = fileMetadata.Requests;

        if (!requests.Remove(fileWatcherRequest.Id))
        {
            Log.UnknownObserver(_logger, path);
            return;
        }

        Log.RemovedObserver(_logger, path);

        // If we found fileMetadata, there must be a containing/corresponding dirMetadata
        var dirMetadata = _metadataForDirectory[dir];

        if (requests.Count == 0)
        {
            fileMetadata.Dispose();
            _metadataForFile.Remove(path);
            dirMetadata.FileWatchCount--;

            Log.RemovedFileWatcher(_logger, path);

            if (dirMetadata.FileWatchCount == 0)
            {
                dirMetadata.Dispose();
                _metadataForDirectory.Remove(dir);

                Log.RemovedDirectoryWatcher(_logger, dir);
            }
        }

        Log.ObserverCount(_logger, path, requests.Count);
        Log.FileCount(_logger, dir, dirMetadata.FileWatchCount);
    }

    /// <remarks>Test hook</remarks>
    internal int TestGetDirectoryWatchCountUnsynchronized() => _metadataForDirectory.Count;

    /// <remarks>Test hook</remarks>
    internal int TestGetFileWatchCountUnsynchronized(string dir) => _metadataForDirectory.TryGetValue(dir, out var metadata) ? metadata.FileWatchCount : 0;

    /// <remarks>Test hook</remarks>
    internal int TestGetObserverCountUnsynchronized(string path) => _metadataForFile.TryGetValue(path, out var metadata) ? metadata.Requests.Count : 0;

    void IDisposable.Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        foreach (var dirMetadata in _metadataForDirectory.Values)
        {
            dirMetadata.Dispose();
        }

        foreach (var fileMetadata in _metadataForFile.Values)
        {
            fileMetadata.Dispose();
        }

        _metadataForDirectory.Clear();
        _metadataForFile.Clear();
    }

    private sealed class DirectoryWatchMetadata(IFileProvider fileProvider) : IDisposable
    {
        public readonly IFileProvider FileProvider = fileProvider;
        public int FileWatchCount;

        public void Dispose() => (FileProvider as IDisposable)?.Dispose();
    }

    private sealed class FileWatchMetadata(IDisposable disposable) : IDisposable
    {
        public readonly IDisposable Disposable = disposable;
        public readonly Dictionary<string, FileChanged> Requests = new();

        public void Dispose() => Disposable.Dispose();
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, string, Exception?> _directoryDoesNotExistCallback =
               LoggerMessage.Define<string, string>(
                   LogLevel.Warning,
                   EventIds.DirectoryDoesNotExist,
                   "Directory '{Directory}' does not exist so changes to the certificate '{Path}' will not be tracked.");


        public static void DirectoryDoesNotExist(ILogger logger, string directory, string path)
        {
            _directoryDoesNotExistCallback(logger, directory, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _unknownFileCallback =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                EventIds.UnknownFile,
                "Attempted to remove watch from unwatched path '{Path}'.");


        public static void UnknownFile(ILogger logger, string path)
        {
            _unknownFileCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _unknownObserverCallback =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                EventIds.UnknownObserver,
                "Attempted to remove unknown observer from path '{Path}'.");


        public static void UnknownObserver(ILogger logger, string path)
        {
            _unknownObserverCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _createdDirectoryWatcherCallback =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                EventIds.CreatedDirectoryWatcher,
                "Created directory watcher for '{Directory}'.");


        public static void CreatedDirectoryWatcher(ILogger logger, string directory)
        {
            _createdDirectoryWatcherCallback(logger, directory, null);
        }

        private static readonly Action<ILogger, string, Exception?> _createdFileWatcherCallback =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                EventIds.CreatedFileWatcher,
                "Created file watcher for '{Path}'.");


        public static void CreatedFileWatcher(ILogger logger, string path)
        {
            _createdFileWatcherCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _removedDirectoryWatcherCallback =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                EventIds.RemovedDirectoryWatcher,
                "Removed directory watcher for '{Directory}'.");

        public static void RemovedDirectoryWatcher(ILogger logger, string directory)
        {
            _removedDirectoryWatcherCallback(logger, directory, null);
        }

        private static readonly Action<ILogger, string, Exception?> _removedFileWatcherCallback =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                EventIds.RemovedFileWatcher,
                "Removed file watcher for '{Path}'.");


        public static void RemovedFileWatcher(ILogger logger, string path)
        {
            _removedFileWatcherCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _lastModifiedTimeErrorCallback =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                EventIds.LastModifiedTimeError,
                "Error retrieving last modified time for '{Path}'.");


        public static void LastModifiedTimeError(ILogger logger, string path, Exception e)
        {
            _lastModifiedTimeErrorCallback(logger, path, e);
        }

        private static readonly Action<ILogger, string, Exception?> _untrackedFileEventCallback =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                EventIds.UntrackedFileEvent,
                "Ignored event for presently untracked file '{Path}'.");


        public static void UntrackedFileEvent(ILogger logger, string path)
        {
            _untrackedFileEventCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _reusedObserverCallback =
            LoggerMessage.Define<string>(
                LogLevel.Trace,
                EventIds.ReusedObserver,
                "Reused existing observer on file watcher for '{Path}'.");


        public static void ReusedObserver(ILogger logger, string path)
        {
            _reusedObserverCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _addedObserverCallback =
            LoggerMessage.Define<string>(
                LogLevel.Trace,
                EventIds.AddedObserver,
                "Added observer to file watcher for '{Path}'.");

        public static void AddedObserver(ILogger logger, string path)
        {
            _addedObserverCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _removedObserverCallback =
            LoggerMessage.Define<string>(
                LogLevel.Trace,
                EventIds.RemovedObserver,
                "Removed observer from file watcher for '{Path}'.");

        public static void RemovedObserver(ILogger logger, string path)
        {
            _removedObserverCallback(logger, path, null);
        }

        private static readonly Action<ILogger, string, int, Exception?> _observerCountCallback =
            LoggerMessage.Define<string, int>(
                LogLevel.Trace,
                EventIds.ObserverCount, "File '{Path}' now has {Count} observers.");

        public static void ObserverCount(ILogger logger, string path, int count)
        {
            _observerCountCallback(logger, path, count, null);
        }

        private static readonly Action<ILogger, string, int, Exception?> _fileCountCallback =
            LoggerMessage.Define<string, int>(
                LogLevel.Trace,
                EventIds.FileCount,
                "Directory '{Directory}' now has watchers on {Count} files.");

        public static void FileCount(ILogger logger, string directory, int count)
        {
            _fileCountCallback(logger, directory, count, null);
        }

        private static readonly Action<ILogger, int, string, Exception?> _flaggedObservers =
            LoggerMessage.Define<int, string>(
                LogLevel.Trace,
                EventIds.EventWithoutFile,
                "Flagged {Count} observers of '{Path}' as changed.");
        public static void FlaggedObservers(ILogger logger, string path, int count)
        {
            _flaggedObservers(logger, count, path, null);
        }

        private static readonly Action<ILogger, string, Exception?> _eventWithoutFileCallback =
            LoggerMessage.Define<string>(
                LogLevel.Trace,
                EventIds.EventWithoutFileCallback,
                "Ignored event since '{Path}' was unavailable.");

        public static void EventWithoutFile(ILogger logger, string path)
        {
            _eventWithoutFileCallback(logger, path, null);
        }
    }
}
