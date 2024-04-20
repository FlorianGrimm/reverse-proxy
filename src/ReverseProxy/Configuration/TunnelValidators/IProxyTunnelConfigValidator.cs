using System;
using System.Collections.Generic;
using System.Linq;

namespace Yarp.ReverseProxy.Configuration.TunnelValidators;

internal interface IProxyTunnelConfigValidator
{
    public void ValidateTunnelBackendToFrontendConfig(TunnelBackendToFrontendConfig tunnel, IList<Exception> errors);
    public void ValidateTunnelFrontendToBackendConfig(TunnelFrontendToBackendConfig tunnel, IList<Exception> errors);
}

internal class ProxyTunnelConfigValidator : IProxyTunnelConfigValidator
{
    private readonly IProxyTunnelBackendToFrontendConfigValidator[] _backendToFrontendConfigValidators;
    private readonly IProxyTunnelFrontendToBackendConfigValidator[] _frontendToBackendConfigValidators;

    public ProxyTunnelConfigValidator(
        IEnumerable<IProxyTunnelBackendToFrontendConfigValidator>? backendToFrontendConfigValidators,
        IEnumerable<IProxyTunnelFrontendToBackendConfigValidator>? frontendToBackendConfigValidators
        )
    {
        _backendToFrontendConfigValidators = backendToFrontendConfigValidators?.ToArray() ?? [];
        _frontendToBackendConfigValidators = frontendToBackendConfigValidators?.ToArray() ?? [];
    }

    public void ValidateTunnelBackendToFrontendConfig(TunnelBackendToFrontendConfig tunnel, IList<Exception> errors)
    {
        foreach(var validator in _backendToFrontendConfigValidators)
        {
            validator.Validate(tunnel, errors);
        }
    }

    public void ValidateTunnelFrontendToBackendConfig(TunnelFrontendToBackendConfig tunnel, IList<Exception> errors)
    {
        foreach (var validator in _frontendToBackendConfigValidators)
        {
            validator.Validate(tunnel, errors);
        }
    }
}
