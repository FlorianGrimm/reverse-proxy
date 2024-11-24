// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

public static class TunnelAuthenticationBasicExtension
{
    public static void Bind(this TunnelAuthenticationBasicOptions options, IConfiguration configuration) {
        if (configuration.GetSection(nameof(TunnelAuthenticationBasicOptions.Password)).Value is { Length: > 0 } valuePassword) {
            options.Password = valuePassword;
        }
    }
}

