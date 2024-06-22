using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Model;

public sealed class TunnelModel
{
    public TunnelModel(TunnelConfig config)
    {
        Config = config;
    }

    public TunnelConfig Config { get; }

    internal bool HasConfigChanged(TunnelModel newModel)
    {
        return !Config.Equals(newModel.Config);
    }
}
