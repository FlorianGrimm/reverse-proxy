using System;
using System.Collections.Generic;

namespace Yarp.ReverseProxy.Configuration.TunnelValidators;

public interface IProxyTunnelBackendToFrontendConfigValidator
{
    public void Validate(TunnelBackendToFrontendConfig tunnel, IList<Exception> errors);
}
