using System;

namespace Yarp.ReverseProxy.Model;

public sealed class TunnelState
{
    private TunnelModel? _model;

    internal TunnelState(string tunnelId)
    {
        TunnelId = tunnelId;
    }

    public TunnelState(string tunnelId, TunnelModel model)
    {
        TunnelId = tunnelId;
        Model = model;
    }

    public string TunnelId { get; }

    public TunnelModel Model { get => _model ?? throw new InvalidOperationException("Model is null"); internal set => _model = value; }

    public int Revision { get; internal set; }

}
