using System;
using System.Net.Http;

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy.Forwarder;

internal sealed class ForwarderMissconfiguredHttpClientFactory
    : ForwarderBaseHttpClientFactory
{
    public ForwarderMissconfiguredHttpClientFactory(
        ILogger logger
        ) : base(logger)
    {
    }

    public override HttpMessageInvoker CreateClient(ForwarderHttpClientContext context)
    {
        throw new Exception("Miss configured");
    }
}
