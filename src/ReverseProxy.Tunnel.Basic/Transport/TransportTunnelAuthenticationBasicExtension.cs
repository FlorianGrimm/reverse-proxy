// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;

namespace Yarp.ReverseProxy.Transport;

public static class TransportTunnelAuthenticationBasicExtension
{
    public static void Bind(this TransportTunnelAuthenticationBasicOptions options, IConfiguration configuration)
    {
        if (configuration.GetSection(nameof(TransportTunnelAuthenticationBasicOptions.Password)).Value is { Length: > 0 } valuePassword)
        {
            options.Password = valuePassword;
        }
    }
}
