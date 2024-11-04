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

    /// <summary>
    /// Get the value and transfer the ownership.
    /// </summary>
    /// <returns>the value</returns>
    T GiveAway();
}

/// <summary>
/// A value that is shared until this is disposed.
/// </summary>
/// <typeparam name="T">The value type</typeparam>
public sealed class Shared<T>
    : IShared<T>
    , IDisposable
{
    public static Action<T, bool> NoOpDispose = (_, _) => { };
    public static Action<T> NoOpGiveAway = (_) => { };

    private T _value;
    private Action<T, bool>? _onDispose;
    private Action<T>? _onGiveAway;

    /// <summary>
    /// Create a new instance of <see cref="Shared{T}"/>.
    /// </summary>
    /// <param name="value">the value</param>
    /// <param name="onDispose">
    /// a callback, which is called on this.Dispose - only once.
    /// If this.Dispose is not called - (may be) the finalizer Garbage Collection fires this (2cd parameter is true).
    /// </param>
    /// <param name="onGiveAway"></param>
    public Shared(T value, Action<T, bool>? onDispose = default, Action<T>? onGiveAway = default)
    {
        _value = value;
        _onDispose = onDispose ?? NoOpDispose;
        _onGiveAway = onGiveAway ?? NoOpGiveAway;
    }

    /// <summary>
    /// Gets the value until this is disposed.
    /// </summary>
    public T Value
    {
        get
        {
            if (_onDispose is null || _onGiveAway is null)
            {
                throw new ObjectDisposedException(nameof(Shared<T>));
            }
            return _value;
        }
    }

    public T GiveAway()
    {
        if (_onDispose is null || _onGiveAway is null)
        {
            throw new ObjectDisposedException(nameof(Shared<T>));
        }

        var result = _value;
        var onGiveAway = _onGiveAway;
        _onDispose = default;
        _onGiveAway = default!;
        _value = default!;
        onGiveAway(result);
        System.GC.SuppressFinalize(this);
        return result;
    }
    private void Dispose(bool disposing)
    {
        if (_onDispose is { } onDispose)
        {
            _onGiveAway = default!;
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
