// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.FileProviders.Physical;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Utilities;

// copy from https://github.com/dotnet/aspnetcore.git src\Servers\Kestrel\Core\src\Internal\CertificatePathWatcher.cs
// renamed to avoid conflicts with the original

public interface IYarpCertificatePathWatcher : IDisposable
{

    /// <summary>
    /// Returns a token that will fire when any watched <see cref="CertificateConfig"/> is changed on disk.
    /// The affected <see cref="CertificateConfig"/> will have <see cref="CertificateConfig.GetFileHasChanged()"/>
    /// set to <code>true</code>.
    /// </summary>
    IChangeToken GetChangeToken();

    /// <summary>
    /// Start watching a certificate's file path for changes.
    /// </summary>
    /// <param name="certificateConfig">the config defines the file path.</param>
    void AddWatch(CertificateConfig certificateConfig);

    /// <summary>
    /// Stop watching a certificate's file path for changes.
    /// </summary>
    /// <param name="certificateConfig">the config defines the file path.</param>
    void RemoveWatch(CertificateConfig certificateConfig);

    /// <summary>
    /// Update the set of <see cref="CertificateConfig"/>s being watched for file changes.
    /// If a given <see cref="CertificateConfig"/> appears in both lists, it is first removed and then added.
    /// </summary>
    /// <remarks>
    /// Does not consider targets when watching files that are symlinks.
    /// </remarks>
    void UpdateWatches(List<CertificateConfig> certificateConfigsToRemove, List<CertificateConfig> certificateConfigsToAdd);
}

internal sealed partial class YarpCertificatePathWatcher: IYarpCertificatePathWatcher, IDisposable
{
    private readonly Func<string, IFileProvider?> _fileProviderFactory;
    private readonly string _contentRootDir;
    private readonly ILogger _logger;

    private readonly object _metadataLock = new();

    /// <remarks>Acquire <see cref="_metadataLock"/> before accessing.</remarks>
    private readonly Dictionary<string, DirectoryWatchMetadata> _metadataForDirectory = new();
    /// <remarks>Acquire <see cref="_metadataLock"/> before accessing.</remarks>
    private readonly Dictionary<string, FileWatchMetadata> _metadataForFile = new();

    private ConfigurationReloadToken _reloadToken = new();
    private bool _disposed;

    public YarpCertificatePathWatcher(
        IOptions<YarpCertificateLoaderOptions> options,
        IHostEnvironment hostEnvironment,
        ILogger<YarpCertificatePathWatcher> logger)
        : this(
            options.Value.CertificateRoot is { Length: > 0 } certificateRoot ? certificateRoot : hostEnvironment.ContentRootPath,
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

    /// <remarks>
    /// For testing.
    /// </remarks>
    internal YarpCertificatePathWatcher(
        string contentRootPath,
        ILogger<YarpCertificatePathWatcher> logger,
        Func<string, IFileProvider?>? fileProviderFactory = null)
    {
        _contentRootDir = contentRootPath;
        _logger = logger;
        _fileProviderFactory = fileProviderFactory ?? CreatePhysicalFileProvider;
    }

    /// <summary>
    /// Returns a token that will fire when any watched <see cref="CertificateConfig"/> is changed on disk.
    /// The affected <see cref="CertificateConfig"/> will have <see cref="CertificateConfig.GetFileHasChanged()"/>
    /// set to <code>true</code>.
    /// </summary>
    public IChangeToken GetChangeToken()
    {
        return _reloadToken;
    }

    /// <summary>
    /// Update the set of <see cref="CertificateConfig"/>s being watched for file changes.
    /// If a given <see cref="CertificateConfig"/> appears in both lists, it is first removed and then added.
    /// </summary>
    /// <remarks>
    /// Does not consider targets when watching files that are symlinks.
    /// </remarks>
    public void UpdateWatches(List<CertificateConfig> certificateConfigsToRemove, List<CertificateConfig> certificateConfigsToAdd)
    {
        var addSet = new HashSet<CertificateConfig>(certificateConfigsToAdd, ReferenceEqualityComparer.Instance);
        var removeSet = new HashSet<CertificateConfig>(certificateConfigsToRemove, ReferenceEqualityComparer.Instance);

        // Don't remove anything we're going to re-add anyway.
        // Don't remove such items from addSet to guard against the (hypothetical) possibility
        // that a caller might remove a config that isn't already present.
        removeSet.ExceptWith(certificateConfigsToAdd);

        if (addSet.Count == 0 && removeSet.Count == 0)
        {
            return;
        }

        lock (_metadataLock)
        {
            // Adds before removes to increase the chances of watcher reuse.
            // Since removeSet doesn't contain any of these configs, this won't change the semantics.
            foreach (var certificateConfig in addSet)
            {
                AddWatchUnsynchronized(certificateConfig);
            }

            foreach (var certificateConfig in removeSet)
            {
                RemoveWatchUnsynchronized(certificateConfig);
            }
        }
    }

    /// <summary>
    /// Start watching a certificate's file path for changes.
    /// </summary>
    /// <param name="certificateConfig">the config defines the file path.</param>
    public void AddWatch(CertificateConfig certificateConfig)
    {
        lock (_metadataLock)
        {
            AddWatchUnsynchronized(certificateConfig);
        }
    }

    /// <summary>
    /// Start watching a certificate's file path for changes.
    /// <paramref name="certificateConfig"/> must have <see cref="CertificateConfig.IsFileCert"/> set to <code>true</code>.
    /// </summary>
    /// <remarks>
    /// Internal for testing.
    /// </remarks>
    private void AddWatchUnsynchronized(CertificateConfig certificateConfig)
    {
        Debug.Assert(certificateConfig.IsFileCert(), "AddWatch called on non-file cert");

        var path = Path.Combine(_contentRootDir, certificateConfig.Path);
        var dir = Path.GetDirectoryName(path)!;

        if (!_metadataForDirectory.TryGetValue(dir, out var dirMetadata))
        {
            // If we wanted to detected deletions of this whole directory (which we don't since we ignore deletions),
            // we'd probably need to watch the whole directory hierarchy

            var fileProvider = _fileProviderFactory(dir);
            if (fileProvider is null)
            {
                Log.DirectoryDoesNotExist(_logger, dir, path);
                return;
            }

            dirMetadata = new DirectoryWatchMetadata(fileProvider);
            _metadataForDirectory.Add(dir, dirMetadata);

            Log.CreatedDirectoryWatcher(_logger, dir);
        }

        if (!_metadataForFile.TryGetValue(path, out var fileMetadata))
        {
            // PhysicalFileProvider appears to be able to tolerate non-existent files, as long as the directory exists

            var disposable = ChangeToken.OnChange(
                () => dirMetadata.FileProvider.Watch(Path.GetFileName(path)),
                static tuple => tuple.Item1.OnChange(tuple.Item2),
                ValueTuple.Create(this, path));

            fileMetadata = new FileWatchMetadata(disposable);
            _metadataForFile.Add(path, fileMetadata);
            dirMetadata.FileWatchCount++;

            Log.CreatedFileWatcher(_logger, path);
        }

        if (!fileMetadata.Configs.Add(certificateConfig))
        {
            Log.ReusedObserver(_logger, path);
            return;
        }

        Log.AddedObserver(_logger, path);

        Log.ObserverCount(_logger, path, fileMetadata.Configs.Count);
        Log.FileCount(_logger, dir, dirMetadata.FileWatchCount);
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

            var configs = fileMetadata.Configs;
            foreach (var config in configs)
            {
                config.SetFileHasChanged(true);
            }

            Log.FlaggedObservers(_logger, path, configs.Count);
        }

        // AddWatch and RemoveWatch don't affect the token, so this doesn't need to be under the semaphore.
        // It does however need to be synchronized, since there could be multiple concurrent events.
        var previousToken = Interlocked.Exchange(ref _reloadToken, new());
        previousToken.OnReload();
    }

    /// <summary>
    /// Stop watching a certificate's file path for changes.
    /// </summary>
    /// <param name="certificateConfig">the config defines the file path.</param>
    public void RemoveWatch(CertificateConfig certificateConfig)
    {
        lock (_metadataLock)
        {
            RemoveWatchUnsynchronized(certificateConfig);
        }
    }

    /// <summary>
    /// Stop watching a certificate's file path for changes (previously started by <see cref="AddWatchUnsynchronized"/>.
    /// <paramref name="certificateConfig"/> must have <see cref="CertificateConfig.IsFileCert"/> set to <code>true</code>.
    /// </summary>
    /// <remarks>
    /// Internal for testing.
    /// </remarks>
    private void RemoveWatchUnsynchronized(CertificateConfig certificateConfig)
    {
        Debug.Assert(certificateConfig.IsFileCert(), "RemoveWatch called on non-file cert");

        var path = Path.Combine(_contentRootDir, certificateConfig.Path);
        var dir = Path.GetDirectoryName(path)!;

        if (!_metadataForFile.TryGetValue(path, out var fileMetadata))
        {
            Log.UnknownFile(_logger, path);
            return;
        }

        var configs = fileMetadata.Configs;

        if (!configs.Remove(certificateConfig))
        {
            Log.UnknownObserver(_logger, path);
            return;
        }

        Log.RemovedObserver(_logger, path);

        // If we found fileMetadata, there must be a containing/corresponding dirMetadata
        var dirMetadata = _metadataForDirectory[dir];

        if (configs.Count == 0)
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

        Log.ObserverCount(_logger, path, configs.Count);
        Log.FileCount(_logger, dir, dirMetadata.FileWatchCount);
    }

    /// <remarks>Test hook</remarks>
    internal int TestGetDirectoryWatchCountUnsynchronized() => _metadataForDirectory.Count;

    /// <remarks>Test hook</remarks>
    internal int TestGetFileWatchCountUnsynchronized(string dir) => _metadataForDirectory.TryGetValue(dir, out var metadata) ? metadata.FileWatchCount : 0;

    /// <remarks>Test hook</remarks>
    internal int TestGetObserverCountUnsynchronized(string path) => _metadataForFile.TryGetValue(path, out var metadata) ? metadata.Configs.Count : 0;

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
        public readonly HashSet<CertificateConfig> Configs = new(ReferenceEqualityComparer.Instance);

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
