using System;
using System.Collections.Generic;

namespace Yarp.ReverseProxy.Configuration.TunnelValidators;

public interface IProxyTunnelFrontendToBackendConfigValidator
{
    public void Validate(TunnelFrontendToBackendConfig tunnel, IList<Exception> errors);
}
