using System;
using System.Collections.Generic;

namespace Yarp.ReverseProxy.Configuration.TunnelValidators;

internal class ProxyTunnelFrontendToBackendConfigValidator: IProxyTunnelFrontendToBackendConfigValidator
{
    public void Validate(TunnelFrontendToBackendConfig tunnel, IList<Exception> errors)
    {
        if (string.IsNullOrEmpty(tunnel.TunnelId))
        {
            errors.Add(new ArgumentException("Missing Tunnel Id."));
        }

        foreach (var c in tunnel.TunnelId)
        {
            if (!char.IsLetterOrDigit(c))
            {
                errors.Add(new ArgumentException("TunnelId must be alphanumeric."));
                break;
            }
        }

        if (string.IsNullOrEmpty(tunnel.Transport))
        {
            errors.Add(new ArgumentException("Missing Transport."));
        }

        // TODO: check if the transport is valid
    }
}
