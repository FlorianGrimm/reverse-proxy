using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Model;

public class TunnelFrontendToBackendState
{
    public TunnelFrontendToBackendConfig Config { get; set; } = default!;

    internal AtomicCounter ConcurrencyCounter { get; } = new AtomicCounter();

    internal int Revision { get; set; }
}

public class TunnelFrontendModel
{
    public TunnelFrontendModel(
        TunnelFrontendToBackendState tunnelFrontend
        )
    {
        TunnelFrontend = tunnelFrontend;
    }

    public TunnelFrontendToBackendState TunnelFrontend { get; }

    internal bool HasConfigChanged(TunnelFrontendModel newTunnelFrontend)
    {
        return !TunnelFrontend.Equals(newTunnelFrontend.TunnelFrontend) /* || newModel.HttpClient != HttpClient */;
    }
}
