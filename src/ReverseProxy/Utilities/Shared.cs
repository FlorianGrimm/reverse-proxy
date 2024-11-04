using System;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// A value that is shared until this is disposed.
/// </summary>
/// <typeparam name="T">The value type</typeparam>
public interface IShared<T>
    : IDisposable
{
    /// <summary>
    /// Gets the value until this is disposed.
    /// </summary>
    T Value { get; }
}

/// <summary>
/// A value that is shared until this is disposed.
/// </summary>
/// <typeparam name="T">The value type</typeparam>
public sealed class Shared<T>
    : IShared<T>
    , IDisposable
{
    public static Action<T, bool> Noop = (_, _) => { };

    private T _value;
    private Action<T, bool>? _onDispose;

    /// <summary>
    /// Create a new instance of <see cref="Shared{T}"/>.
    /// </summary>
    /// <param name="value">the value</param>
    /// <param name="onDispose">
    /// a callback, which is called on this.Dispose - only once.
    /// If this.Dispose is not called - (may be) the finalizier Garbage Collection fires this (2cd parameter is true).
    /// </param>
    public Shared(T value, Action<T, bool> onDispose)
    {
        _value = value;
        _onDispose = onDispose;
    }

    /// <summary>
    /// Gets the value until this is disposed.
    /// </summary>
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
