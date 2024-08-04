// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy;

internal static class EventIds
{

    public static readonly EventId MissingOrInvalidCertificateFile = new EventId(76, "MissingOrInvalidCertificateFile");
    public static readonly EventId MissingOrInvalidCertificateKeyFile = new EventId(77, "MissingOrInvalidCertificateKeyFile");
    public static readonly EventId SuccessfullyLoadedCertificateKey = new EventId(97, "SuccessfullyLoadedCertificateKey");

    public static readonly EventId DirectoryDoesNotExist = new EventId(78, "DirectoryDoesNotExist");
    public static readonly EventId UnknownFile = new EventId(79, "UnknownFile");
    public static readonly EventId UnknownObserver = new EventId(80, "UnknownObserver");
    public static readonly EventId CreatedDirectoryWatcher = new EventId(81, "CreatedDirectoryWatcher");
    public static readonly EventId CreatedFileWatcher = new EventId(82, "CreatedFileWatcher");
    public static readonly EventId RemovedDirectoryWatcher = new EventId(83, "RemovedDirectoryWatcher");
    public static readonly EventId RemovedFileWatcher = new EventId(84, "RemovedFileWatcher");
    public static readonly EventId LastModifiedTimeError = new EventId(85, "LastModifiedTimeError");
    public static readonly EventId UntrackedFileEvent = new EventId(86, "UntrackedFileEvent");
    public static readonly EventId ReusedObserver = new EventId(87, "ReusedObserver");
    public static readonly EventId AddedObserver = new EventId(88, "AddedObserver");
    public static readonly EventId RemovedObserver = new EventId(89, "RemovedObserver");
    public static readonly EventId ObserverCount = new EventId(90, "ObserverCount");
    public static readonly EventId FileCount = new EventId(90, "FileCount");
    public static readonly EventId EventWithoutFile = new EventId(91, "EventWithoutFile");
    public static readonly EventId EventWithoutFileCallback = new EventId(92, "EventWithoutFileCallback");

    public static readonly EventId ClusterAuthenticationSuccess = new EventId(95, "ClusterAuthenticationSuccess");
    public static readonly EventId ClusterAuthenticationFailed = new EventId(96, "ClusterAuthenticationFailed");
}
