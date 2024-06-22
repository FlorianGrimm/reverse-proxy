using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Model;
public sealed class TunnelState
{
    private TunnelModel _Model = null!;

    public TunnelState(string tunnelId)
    {
        TunnelId = tunnelId;
    }

    public TunnelState(string tunnelId, TunnelModel model)
    {
        TunnelId = tunnelId;
        Model = model;
    }

    public string TunnelId { get; }

    public TunnelModel Model { get => _Model; internal set => _Model = value; }

    public int Revision { get; internal set; }
}
