using System;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// A value that is shared until this is disposed.
/// </summary>
/// <typeparam name="T">The value type</typeparam>
public interface ISharedValue<T>
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
