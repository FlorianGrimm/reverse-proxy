using System;

using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Utilities;

internal abstract class UnShortCircuitRequiredService<T>
    where T : notnull
{
    protected readonly IServiceProvider _serviceProvider;
    private T? _value;
    private bool _resolved;

    public UnShortCircuitRequiredService(
        IServiceProvider serviceProvider
        )
    {
        _serviceProvider = serviceProvider;
    }

    public T GetService()
    {
        if (_resolved && _value is T value)
        {
            return value;
        }
        else
        {
            _resolved = true;
            return _value = Resolve();
        }
    }

    protected virtual T Resolve()
    {
        return _serviceProvider.GetRequiredService<T>();
    }
}
