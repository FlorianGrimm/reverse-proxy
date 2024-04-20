// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Yarp.ReverseProxy.Forwarder;

/// <summary>
/// Default implementation of <see cref="IForwarderHttpClientFactory"/>.
/// </summary>
public class ForwarderHttpClientFactory : ForwarderBaseClientFactory, IForwarderHttpClientFactory, IForwarderHttpClientFactorySelectiv
{
    public const string Transport = "Http";

    /// <summary>
    /// Initializes a new instance of the <see cref="ForwarderHttpClientFactory"/> class.
    /// </summary>
    public ForwarderHttpClientFactory() : this(NullLogger<ForwarderHttpClientFactory>.Instance) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ForwarderHttpClientFactory"/> class.
    /// </summary>
    public ForwarderHttpClientFactory(ILogger<ForwarderHttpClientFactory> logger) : base(logger) { }

    public override string GetTransport()
    {
        return Transport;
    }
}
