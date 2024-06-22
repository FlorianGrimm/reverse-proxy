using System;

using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Utilities;

internal abstract class UnShortCircuitOptionalService<T>
    where T : notnull
{
    protected readonly IServiceProvider _serviceProvider;
    private T? _value;
    private bool _resolved;

    public UnShortCircuitOptionalService(
        IServiceProvider serviceProvider
        )
    {
        _serviceProvider = serviceProvider;
    }

    public T? GetService()
    {
        if (_resolved)
        {
            return _value;
        }
        else
        {
            _resolved = true;
            return _value = Resolve();
        }
    }

    protected virtual T? Resolve()
    {
        return _serviceProvider.GetService<T>();
    }
}
