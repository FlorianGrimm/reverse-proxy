using Microsoft.Extensions.Configuration;

using Yarp.ReverseProxy.Tunnel;

namespace Yarp.ReverseProxy.Configuration;

public class TunnelBackendConfig
{
    // "https://localhost:7244/connect-h2?host=backend1.app"
    public string Url { get; set; } = default!;

    public int MaxConnectionCount { get; set; } = 10;

    public TransportType Transport { get; set; }
}

internal static class TunnelBackendConfigProvider {
    public static TunnelBackendConfig GetTunnelBackendConfig(IConfiguration configuration) {
        return new TunnelBackendConfig()
        {
            Url = configuration[nameof(TunnelBackendConfig.Url)]??string.Empty,
            MaxConnectionCount = configuration.ReadInt32(nameof(TunnelBackendConfig.MaxConnectionCount)).GetValueOrDefault(10),
            Transport = configuration.ReadEnum<TransportType>(nameof(TunnelBackendConfig.Transport)).GetValueOrDefault(TransportType.Disabled)
        };
    }
}
