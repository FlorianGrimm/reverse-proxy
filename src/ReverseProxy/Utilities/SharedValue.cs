using System;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// A value that is shared until this is disposed.
/// </summary>
/// <typeparam name="TValue">The value type</typeparam>
/// <typeparam name="TExtra">A extra value type</typeparam>
internal sealed class SharedValue<TValue, TExtra>
    : ISharedValue<TValue>
    , IDisposable
{
    public static Action<TValue, TExtra, bool> NoOpDispose = (_,_, _) => { };
    public static Action<TValue, TExtra> NoOpGiveAway = (_, _) => { };

    private TValue _value;
    private TExtra _extra;
    private Action<TValue, TExtra, bool>? _onDispose;
    private Action<TValue, TExtra>? _onGiveAway;

    /// <summary>
    /// Create a new instance of <see cref="SharedValue{TValue, TExtra}"/>.
    /// </summary>
    /// <param name="value">the value</param>
    /// <param name="extra">a extra value</param>
    /// <param name="onDispose">
    /// a callback, which is called on this.Dispose - only once.
    /// If this.Dispose is not called - (may be) the finalizer Garbage Collection fires this (2cd parameter is true).
    /// </param>
    /// <param name="onGiveAway"></param>
    public SharedValue(TValue value, TExtra extra, Action<TValue, TExtra, bool>? onDispose = default, Action<TValue, TExtra>? onGiveAway = default)
    {
        _value = value;
        _extra = extra;
        _onDispose = onDispose ?? NoOpDispose;
        _onGiveAway = onGiveAway ?? NoOpGiveAway;
    }

    /// <summary>
    /// Gets the value until this is disposed.
    /// </summary>
    public TValue Value
    {
        get
        {
            if (_onDispose is null || _onGiveAway is null)
            {
                throw new ObjectDisposedException(nameof(SharedValue<TValue, TExtra>));
            }
            return _value;
        }
    }

    public TExtra Extra
    {
        get
        {
            if (_onDispose is null || _onGiveAway is null)
            {
                throw new ObjectDisposedException(nameof(SharedValue<TValue, TExtra>));
            }
            return _extra;
        }
    }

    public TValue GiveAway()
    {
        if (_onDispose is null || _onGiveAway is null)
        {
            throw new ObjectDisposedException(nameof(SharedValue<TValue, TExtra>));
        }

        var value = _value;
        var extra = _extra;
        var onGiveAway = _onGiveAway;
        _onDispose = default;
        _onGiveAway = default!;
        _value = default!;
        _extra = default!;
        onGiveAway(value, extra);
        System.GC.SuppressFinalize(this);
        return value;
    }

    private void Dispose(bool disposing)
    {
        if (_onDispose is { } onDispose)
        {
            var value = _value;
            var extra = _extra;
            _onGiveAway = default!;
            _onDispose = default;
            _value = default!;
            _extra = default!;
            onDispose(value, extra, disposing);
        }
    }

    ~SharedValue()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        System.GC.SuppressFinalize(this);
    }
}
