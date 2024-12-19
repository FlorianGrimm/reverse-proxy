// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Configuration;

namespace Yarp.ReverseProxy.Transport;

public static class TransportTunnelLoopbackOptionsExtensions
{
    public static void Bind(
        this TransportTunnelLoopbackOptions that,
        IConfiguration configuration
        )
    {
        if (bool.TryParse(
                configuration.GetSection(nameof(TransportTunnelLoopbackOptions.IsEnabled)).Value,
                out var valueIsEnabled))
        {
            that.IsEnabled = valueIsEnabled;
        }

        if (int.TryParse(
                configuration.GetSection(nameof(TransportTunnelLoopbackOptions.MaxConnectionCount)).Value,
                System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture,
                out var valueMaxConnectionCount)
            && (0 <= valueMaxConnectionCount))
        {
            that.MaxConnectionCount = valueMaxConnectionCount;
        }
    }
}
