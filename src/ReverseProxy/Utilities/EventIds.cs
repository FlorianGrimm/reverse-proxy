// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy;

internal static class EventIds
{
    public static readonly EventId LoadData = new EventId(1, "ApplyProxyConfig");
    public static readonly EventId ErrorSignalingChange = new EventId(2, "ApplyProxyConfigFailed");
    public static readonly EventId NoClusterFound = new EventId(4, "NoClusterFound");
    public static readonly EventId NoAvailableDestinations = new EventId(7, "NoAvailableDestinations");
    public static readonly EventId MultipleDestinationsAvailable = new EventId(8, "MultipleDestinationsAvailable");
    public static readonly EventId Forwarding = new EventId(9, "Forwarding");
    public static readonly EventId ExplicitActiveCheckOfAllClustersHealthFailed = new EventId(10, "ExplicitActiveCheckOfAllClustersHealthFailed");
    public static readonly EventId ActiveHealthProbingFailedOnCluster = new EventId(11, "ActiveHealthProbingFailedOnCluster");
    public static readonly EventId ErrorOccuredDuringActiveHealthProbingShutdownOnCluster = new EventId(12, "ErrorOccuredDuringActiveHealthProbingShutdownOnCluster");
    public static readonly EventId ActiveHealthProbeConstructionFailedOnCluster = new EventId(13, "ActiveHealthProbeConstructionFailedOnCluster");
    public static readonly EventId StartingActiveHealthProbingOnCluster = new EventId(14, "StartingActiveHealthProbingOnCluster");
    public static readonly EventId StoppedActiveHealthProbingOnCluster = new EventId(15, "StoppedActiveHealthProbingOnCluster");
    public static readonly EventId DestinationProbingCompleted = new EventId(16, "DestinationActiveProbingCompleted");
    public static readonly EventId DestinationProbingFailed = new EventId(17, "DestinationActiveProbingFailed");
    public static readonly EventId SendingHealthProbeToEndpointOfDestination = new EventId(18, "SendingHealthProbeToEndpointOfDestination");
    public static readonly EventId UnhealthyDestinationIsScheduledForReactivation = new EventId(19, "UnhealthyDestinationIsScheduledForReactivation");
    public static readonly EventId PassiveDestinationHealthResetToUnkownState = new EventId(20, "PassiveDestinationHealthResetToUnkownState");
    public static readonly EventId ClusterAdded = new EventId(21, "ClusterAdded");
    public static readonly EventId ClusterChanged = new EventId(22, "ClusterChanged");
    public static readonly EventId ClusterRemoved = new EventId(23, "ClusterRemoved");
    public static readonly EventId DestinationAdded = new EventId(24, "EndpointAdded");
    public static readonly EventId DestinationChanged = new EventId(25, "EndpointChanged");
    public static readonly EventId DestinationRemoved = new EventId(26, "EndpointRemoved");
    public static readonly EventId RouteAdded = new EventId(27, "RouteAdded");
    public static readonly EventId RouteChanged = new EventId(28, "RouteChanged");
    public static readonly EventId RouteRemoved = new EventId(29, "RouteRemoved");
    public static readonly EventId HttpDowngradeDetected = new EventId(30, "HttpDowngradeDetected");
    public static readonly EventId OperationStarted = new EventId(31, "OperationStarted");
    public static readonly EventId OperationEnded = new EventId(32, "OperationEnded");
    public static readonly EventId OperationFailed = new EventId(33, "OperationFailed");
    public static readonly EventId AffinityResolutionFailedForCluster = new EventId(34, "AffinityResolutionFailedForCluster");
    public static readonly EventId MultipleDestinationsOnClusterToEstablishRequestAffinity = new EventId(35, "MultipleDestinationsOnClusterToEstablishRequestAffinity");
    public static readonly EventId AffinityCannotBeEstablishedBecauseNoDestinationsFoundOnCluster = new EventId(36, "AffinityCannotBeEstablishedBecauseNoDestinationsFoundOnCluster");
    public static readonly EventId NoDestinationOnClusterToEstablishRequestAffinity = new EventId(37, "NoDestinationOnClusterToEstablishRequestAffinity");
    public static readonly EventId RequestAffinityKeyDecryptionFailed = new EventId(38, "RequestAffinityKeyDecryptionFailed");
    public static readonly EventId DestinationMatchingToAffinityKeyNotFound = new EventId(39, "DestinationMatchingToAffinityKeyNotFound");
    public static readonly EventId RequestAffinityHeaderHasMultipleValues = new EventId(40, "RequestAffinityHeaderHasMultipleValues");
    public static readonly EventId AffinityResolutionFailureWasHandledProcessingWillBeContinued = new EventId(41, "AffinityResolutionFailureWasHandledProcessingWillBeContinued");
    public static readonly EventId ClusterConfigException = new EventId(42, "ClusterConfigException");
    public static readonly EventId ErrorReloadingConfig = new EventId(43, "ErrorReloadingConfig");
    public static readonly EventId ErrorApplyingConfig = new EventId(44, "ErrorApplyingConfig");
    public static readonly EventId ClientCreated = new EventId(45, "ClientCreated");
    public static readonly EventId ClientReused = new EventId(46, "ClientReused");
    public static readonly EventId ConfigurationDataConversionFailed = new EventId(47, "ConfigurationDataConversionFailed");
    public static readonly EventId ForwardingError = new EventId(48, "ForwardingError");
    public static readonly EventId ActiveDestinationHealthStateIsSetToUnhealthy = new EventId(49, "ActiveDestinationHealthStateIsSetToUnhealthy");
    public static readonly EventId ActiveDestinationHealthStateIsSet = new EventId(50, "ActiveDestinationHealthStateIsSet");
    public static readonly EventId DelegationQueueInitializationFailed = new EventId(51, "DelegationQueueInitializationFailed");
    public static readonly EventId DelegationQueueNotFound = new EventId(52, "DelegationQueueNotFound");
    public static readonly EventId DelegationQueueNotInitialized  = new EventId(53, "DelegationQueueNotInitialized");
    public static readonly EventId DelegatingRequest = new EventId(54, "DelegatingRequest");
    public static readonly EventId DelegationFailed = new EventId(55, "DelegationFailed");
    public static readonly EventId ResponseReceived = new EventId(56, "ResponseReceived");
    public static readonly EventId DelegationQueueReset = new EventId(57, "DelegationQueueReset");
    public static readonly EventId Http10RequestVersionDetected = new EventId(58, "Http10RequestVersionDetected");
    public static readonly EventId NotForwarding = new EventId(59, "NotForwarding");
    public static readonly EventId MaxRequestBodySizeSet = new EventId(60, "MaxRequestBodySizeSet");
    public static readonly EventId RetryingWebSocketDowngradeNoConnect = new EventId(61, "RetryingWebSocketDowngradeNoConnect");
    public static readonly EventId RetryingWebSocketDowngradeNoHttp2 = new EventId(62, "RetryingWebSocketDowngradeNoHttp2");
    public static readonly EventId InvalidSecWebSocketKeyHeader = new EventId(63, "InvalidSecWebSocketKeyHeader");
    public static readonly EventId TimeoutNotApplied = new(64, nameof(TimeoutNotApplied));
    public static readonly EventId DelegationQueueNoLongerExists = new(65, nameof(DelegationQueueNoLongerExists));
    public static readonly EventId ForwardingRequestCancelled = new(66, nameof(ForwardingRequestCancelled));
    public static readonly EventId TunnelAdded = new EventId(67, "TunnelAdded");
    public static readonly EventId TunnelChanged = new EventId(68, "TunnelChanged");
    public static readonly EventId TunnelRemoved = new EventId(69, "TunnelRemoved");
    public static readonly EventId ParameterNotValid = new EventId(70, "ParameterNotValid");
    public static readonly EventId ClusterNotFound = new EventId(71, "ClusterNotFound");
    public static readonly EventId TunnelConnectionChannelNotFound = new EventId(72, "TunnelConnectionChannelNotFound");
    public static readonly EventId TunnelCreateHttpMessageInvoker = new EventId(73, "TunnelCreateHttpMessageInvoker");
    public static readonly EventId TunnelCannotConnectTunnel = new EventId(74, "TunnelCannotConnectTunnel");
    public static readonly EventId TunnelResumeConnectTunnel = new EventId(75, "TunnelResumeConnectTunnel");

    public static readonly EventId TransportWebSocketAcceptFailed = new EventId(93, "TransportWebSocketAcceptFailed");
    public static readonly EventId TransportHttp2AcceptFailed = new EventId(94, "TransportHttp2AcceptFailed");
    public static readonly EventId TransportSendTransportTunnel = new EventId(95, "TransportSendTransportTunnel");
    public static readonly EventId TransportConnectCallbackRequestCanceled = new EventId(96, "TransportConnectCallbackRequestCanceled");

    public static readonly EventId MissingOrInvalidCertificateFile = new EventId(76, "MissingOrInvalidCertificateFile");
    public static readonly EventId MissingOrInvalidCertificateKeyFile = new EventId(77, "MissingOrInvalidCertificateKeyFile");

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
    public static readonly EventId SuccessfullyLoadedCertificateKey = new EventId(97, "SuccessfullyLoadedCertificateKey");

    public static readonly EventId NoCertificate = new EventId(120, "NoCertificate");
    public static readonly EventId NotHttps = new EventId(121, "NotHttps");
    public static readonly EventId CertificateRejected = new EventId(122, "CertificateRejected");
    public static readonly EventId CertificateFailedValidation = new EventId(123, "CertificateFailedValidation");
    public static readonly EventId RemoteCertificateValidationSuccess = new EventId(124, "RemoteCertificateValidationSuccess");
    public static readonly EventId RemoteCertificateValidationFailed = new EventId(125, "RemoteCertificateValidationFailed");
    public static readonly EventId ClientCertificateValidationSuccess = new EventId(126, "ClientCertificateValidationSuccess");
    public static readonly EventId ClientCertificateValidationFailed = new EventId(127, "ClientCertificateValidationFailed");

}
