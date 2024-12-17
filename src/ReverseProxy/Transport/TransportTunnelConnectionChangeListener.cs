// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

internal class TransportTunnelConnectionChangeListener : ITunnelChangeListener
{
    public TransportTunnelConnectionChangeListener()
    {
    }

    public void OnTunnelAdded(TunnelState tunnel)
    {
        // TODO: is it possible to add a new listen endpoints in kestrel after start?
    }

    public void OnTunnelChanged(TunnelState tunnel)
    {
    }

    public void OnTunnelRemoved(TunnelState tunnel)
    {
    }
}
