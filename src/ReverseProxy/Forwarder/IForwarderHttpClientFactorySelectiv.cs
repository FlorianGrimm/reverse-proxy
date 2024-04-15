// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Forwarder;

public interface IForwarderHttpClientFactorySelectiv : IForwarderHttpClientFactory
{
    string GetTransport();
}
