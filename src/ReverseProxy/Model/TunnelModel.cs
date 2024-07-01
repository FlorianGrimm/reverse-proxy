using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Model;

public sealed class TunnelModel
{
    public TunnelModel(TransportTunnelConfig config)
    {
        Config = config;
    }

    public TransportTunnelConfig Config { get; }

    internal bool HasConfigChanged(TunnelModel newModel)
    {
        return !Config.Equals(newModel.Config);
    }
}
