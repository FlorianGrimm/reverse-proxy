// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy;

internal static class EventIds
{
    public static readonly EventId ClusterAuthenticationSuccess = new EventId(95, "ClusterAuthenticationSuccess");
    public static readonly EventId ClusterAuthenticationFailed = new EventId(96, "ClusterAuthenticationFailed");
}
