using System.Net.Http;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Model;

public class TunnelBackendState
{
    public string TunnelId => Config.TunnelId;

    public TunnelBackendConfig Config { get; set; } = default!;

    internal AtomicCounter ConcurrencyCounter { get; } = new AtomicCounter();
        
    internal int Revision { get; set; }
}

public class TunnelBackendModel
{
    public TunnelBackendModel(
        TunnelBackendState tunnelBackend
        )
    {
        TunnelBackend = tunnelBackend;
    }

    public TunnelBackendState TunnelBackend { get; }

    internal bool HasConfigChanged(TunnelBackendModel newTunnelBackend)
    {
        return !TunnelBackend.Equals(newTunnelBackend.TunnelBackend) /* || newModel.HttpClient != HttpClient */;
    }
}
