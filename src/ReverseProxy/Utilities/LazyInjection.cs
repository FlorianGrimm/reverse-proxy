using System;

using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Utilities;

public class LazyInjection<T>(IServiceProvider serviceProvider)
    where T : notnull
{
    private readonly IServiceProvider _serviceProvider = serviceProvider;
    private bool _initialized = false;
    private T _value = default!;

    public T GetRequiredService()
    {
        if (!_initialized)
        {
            lock (this)
            {
                if (!_initialized)
                {
                    _value = _serviceProvider.GetRequiredService<T>();
                }
            }
            _initialized = true;
        }
        return _value;
    }
}
