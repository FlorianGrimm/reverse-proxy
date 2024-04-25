using System;
using System.Collections.Generic;

namespace Yarp.ReverseProxy.Configuration.TunnelValidators;

internal class ProxyTunnelBackendToFrontendConfigValidator : IProxyTunnelBackendToFrontendConfigValidator
{
    public void Validate(TunnelBackendToFrontendConfig tunnel, IList<Exception> errors)
    {
        if (string.IsNullOrEmpty(tunnel.TunnelId))
        {
            errors.Add(new ArgumentException("Missing TunnelId."));
        }

        foreach(var c in tunnel.TunnelId)
        {
            if (!char.IsLetterOrDigit(c))
            {
                errors.Add(new ArgumentException("TunnelId must be alphanumeric."));
                break;
            }
        }

        if (string.IsNullOrEmpty(tunnel.RemoteTunnelId))
        {
            errors.Add(new ArgumentException("Missing RemoteTunnelId."));
        }
        foreach (var c in tunnel.RemoteTunnelId)
        {
            if (!char.IsLetterOrDigit(c))
            {
                errors.Add(new ArgumentException("RemoteTunnelId must be alphanumeric."));
                break;
            }
        }

        if (string.IsNullOrEmpty(tunnel.Url))
        {
            errors.Add(new ArgumentException("Missing Url."));
        }

        if (!Uri.TryCreate(tunnel.Url, UriKind.Absolute, out var _)) {
            errors.Add(new ArgumentException("Invalid Url."));
        }

        // TODO: is https required?

        if (string.IsNullOrEmpty(tunnel.Transport))
        {
            errors.Add(new ArgumentException("Missing Transport."));
        }

        // TODO: check if the transport is valid
    }
}
