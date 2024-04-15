using System;
using System.Collections.Generic;
using System.Linq;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Tunnel;

internal class TunnelHandlerFactorySelector : ITunnelHandlerFactory
{
    private readonly ITunnelHandlerFactory[] _tunnelHandlerFactories;

    public TunnelHandlerFactorySelector(
        IEnumerable<ITunnelHandlerFactory> tunnelHandlerFactories
        )
    {
        _tunnelHandlerFactories = tunnelHandlerFactories.ToArray();
    }

    public bool CanCreate(string transport)
    {
        foreach (var factory in _tunnelHandlerFactories)
        {
            if (factory.CanCreate(transport))
            {
                return true;
            }
        }
        return false;
    }

    public ITunnelHandler? Create(TunnelFrontendToBackendState tunnelFrontendToBackend)
    {
        var transport = tunnelFrontendToBackend.GetNormalizedTransport();
        foreach (var factory in _tunnelHandlerFactories) {
            if (factory.CanCreate(transport)) {
                return factory.Create(tunnelFrontendToBackend);
            }
        }
        return null;
    }
}
