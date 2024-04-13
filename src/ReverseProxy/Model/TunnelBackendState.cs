using System.Net.Http;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Model;

public class TunnelBackendToFrontendState
{
    public string TunnelId => Config.TunnelId;

    public TunnelBackendToFrontendConfig Config { get; set; } = default!;

    internal AtomicCounter ConcurrencyCounter { get; } = new AtomicCounter();
        
    internal int Revision { get; set; }
}

public class TunnelBackendModel
{
    public TunnelBackendModel(
        TunnelBackendToFrontendState tunnelBackend
        )
    {
        TunnelBackend = tunnelBackend;
    }

    public TunnelBackendToFrontendState TunnelBackend { get; }

    internal bool HasConfigChanged(TunnelBackendModel newTunnelBackend)
    {
        return !TunnelBackend.Equals(newTunnelBackend.TunnelBackend) /* || newModel.HttpClient != HttpClient */;
    }
}
