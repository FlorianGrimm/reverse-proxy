using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Configuration.TunnelValidators;

public class TunnelUrlValidator : ITunnelValidator
{
    public ValueTask ValidateAsync(TransportTunnelConfig tunnelConfig, IList<Exception> errors)
    {
        if (string.IsNullOrEmpty(tunnelConfig.Url))
        {
            errors.Add(new ArgumentException("Tunnel URL is not set."));
            return ValueTask.CompletedTask;
        }

        var remoteTunnelId = tunnelConfig.GetRemoteTunnelId();
        if (string.IsNullOrEmpty(remoteTunnelId))
        {
            errors.Add(new ArgumentException("Tunnel RemoteTunnelId is not set."));
        }
        {
            var containsInvalidChars = false;
            foreach (var c in remoteTunnelId)
            {
                if (!char.IsLetterOrDigit(c))
                {
                    containsInvalidChars = true;
                    break;
                }
            }
            if (containsInvalidChars)
            {
                errors.Add(new ArgumentException("Tunnel RemoteTunnelId contains invalid characters."));
            }
        }
        if (remoteTunnelId.Length > 100)
        {
            errors.Add(new ArgumentException("Tunnel RemoteTunnelId is too long."));
        }
        return ValueTask.CompletedTask;
    }
}
