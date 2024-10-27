using System;

namespace Yarp.ReverseProxy.Utilities;

public sealed class Shared<T>:IDisposable
{
    private T _value;
    private Action<T, bool>? _onDispose;

    public Shared(T value, Action<T, bool> onDispose)
    {
        _value = value;
        _onDispose = onDispose;
    }

    public T Value
    {
        get
        {
            if (_onDispose is null)
            {
                throw new ObjectDisposedException(nameof(Shared<T>));
            }
            return _value;
        }
    }

    private void Dispose(bool disposing)
    {
        if (_onDispose is { } onDispose)
        {
            _onDispose = default;
            onDispose(_value, disposing);
            _value = default!;
        }
    }

    ~Shared()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        System.GC.SuppressFinalize(this);
    }
}
