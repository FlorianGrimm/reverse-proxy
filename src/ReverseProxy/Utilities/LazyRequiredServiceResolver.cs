using System;

using Microsoft.Extensions.DependencyInjection;

namespace Yarp.ReverseProxy.Utilities;

public interface ILazyRequiredServiceResolver<T> where T : notnull
{
    T GetService();
}

internal abstract class LazyRequiredServiceResolver<T>
    : ILazyRequiredServiceResolver<T>
    where T : notnull
{
    protected readonly IServiceProvider ServiceProvider;
    private T? _value;
    private bool _resolved;

    public LazyRequiredServiceResolver(
        IServiceProvider serviceProvider
        )
    {
        ServiceProvider = serviceProvider;
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
        return ServiceProvider.GetRequiredService<T>();
    }
}
