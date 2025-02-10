// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Allow to release the AsyncLockWithOwner.
/// </summary>
public interface IAsyncLockWithOwner
{
    void Release();
}

/// <summary>
/// <see cref="AsyncLockWithOwner"/> Wraps a <see cref="SemaphoreSlim"/>.
/// <see cref="LockAsync(object?, CancellationToken)"/> is only allowed for a maximum times otherwise it waits.
/// The result is a AsyncLockOwner, which responsiblity is to <see cref="IAsyncLockOwnership.Release"/> after the resource is no more used.
/// The ownership can be transferred. Only if latest owner release it's actual released.
/// </summary>
public sealed class AsyncLockWithOwner
    : IDisposable
    , IAsyncLockWithOwner
{
    private SemaphoreSlim _semaphore;

    public AsyncLockWithOwner(int maximum)
    {
        _semaphore = new SemaphoreSlim(maximum);
    }

    /// <summary>
    /// The current count of the semaphore.
    /// </summary>
    internal int CurrentCount => _semaphore.CurrentCount;

    /// <summary>
    /// This semaphore is disposed.
    /// </summary>
    public bool IsDisposed { get; private set; }

    /// <summary>
    /// Wait for the semaphore.
    /// </summary>
    /// <param name="owner">the owner.</param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public async ValueTask<AsyncLockOwner> LockAsync(object? owner, CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken);
        return AsyncLockOwnership.Create(owner, this);
    }

    /// <summary>
    /// Release the semaphore.
    /// </summary>
    void IAsyncLockWithOwner.Release()
    {
        _semaphore.Release();
    }

    /// <summary>
    /// Dispose the semaphore.
    /// </summary>
    /// <param name="disposing"></param>
    private void Dispose(bool disposing)
    {
        IsDisposed = true;
        using (var semaphore = _semaphore)
        {
            if (disposing)
            {
                _semaphore = null!;
            }
        }
    }

    ~AsyncLockWithOwner()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Defines the operations for the ownership of the AsyncLockWithOwner.
/// </summary>
public interface IAsyncLockOwnership
{
    /// <summary>
    /// Transfer the ownership of the AsyncLockWithOwner(semaphore) to another owner.
    /// </summary>
    /// <typeparam name="T">The type of the owner</typeparam>
    /// <param name="oldOwner">The old owner</param>
    /// <param name="owner">the new owner</param>
    /// <returns>The instance to dispose</returns>
    AsyncLockOwner Transfer<T>(object? oldOwner, T? owner) where T : class;

    /// <summary>
    /// Release the AsyncLockWithOwner(semaphore) if the <paramref name="owner"/> is the current owner.
    /// Calling a second time with the same <paramref name="owner"/> will do nothing and return false.
    /// </summary>
    /// <typeparam name="T">The type of the owner.</typeparam>
    /// <param name="owner">The owner</param>
    /// <returns>True if released - the <paramref name="owner"/> is the current owner.</returns>
    bool Release<T>(T? owner) where T : class;

    /// <summary>
    /// Check if the <paramref name="owner"/> is the current owner.
    /// </summary>
    /// <typeparam name="T">The type of the owner.</typeparam>
    /// <param name="owner">The owner</param>
    /// <returns>true if <see cref="object.ReferenceEquals(object?, object?)"/></returns>
    bool HasOwner<T>(T? owner) where T : class;
}

/// <summary>
/// One semaphore count/step with an owner.
/// </summary>
public sealed class AsyncLockOwnership
    : IAsyncLockOwnership
{
    private static readonly object _notAOwner = new();

    public static AsyncLockOwner Create<T>(T? owner, AsyncLockWithOwner asyncLockWithOwner)
        where T : class
    {
        var asyncLockOwnership = new AsyncLockOwnership(owner, asyncLockWithOwner);
        return new AsyncLockOwner(asyncLockOwnership, owner);
    }

    private object? _owner;
    private readonly IAsyncLockWithOwner _asyncLockWithOwner;

    private AsyncLockOwnership(object? owner, IAsyncLockWithOwner asyncLockWithOwner)
    {
        _owner = owner;
        _asyncLockWithOwner = asyncLockWithOwner;
    }

    AsyncLockOwner IAsyncLockOwnership.Transfer<T>(object? oldOwner, T? owner)
        where T : class
    {
        System.Threading.Interlocked.CompareExchange(ref _owner, owner, oldOwner);
        return new AsyncLockOwner(this, owner);
    }

    bool IAsyncLockOwnership.Release<T>(T? owner)
        where T : class
    {
        if (ReferenceEquals(
            System.Threading.Interlocked.CompareExchange(ref _owner, _notAOwner, owner),
            owner))
        {
            _asyncLockWithOwner.Release();
            return true;
        }
        else
        {
            return false;
        }
    }

    bool IAsyncLockOwnership.HasOwner<T>(T? owner)
        where T : class
    {
        return ReferenceEquals(_owner, owner);
    }
}

/// <summary>
/// Pairs the <see cref="IAsyncLockOwnership"/> with the owner.
/// </summary>
public struct AsyncLockOwner : IDisposable
{
    private readonly IAsyncLockOwnership _asyncLockOwnership;
    private readonly object? _owner;

    internal AsyncLockOwner(IAsyncLockOwnership asyncLockOwnership, object? owner)
    {
        _asyncLockOwnership = asyncLockOwnership;
        _owner = owner;
    }

    /// <summary>
    /// Check if the owner is the current owner.
    /// </summary>
    /// <returns>true if this has the ownership</returns>
    public bool HasOwner()
    {
        return _asyncLockOwnership.HasOwner(_owner);
    }

    /// <summary>
    /// Transfer the ownership of the AsyncLockWithOwner(semaphore) to another owner.
    /// </summary>
    /// <typeparam name="T">The type of the owner</typeparam>
    /// <param name="owner">the new owner</param>
    /// <returns>The instance to dispose</returns>
    public AsyncLockOwner Transfer<T>(T? owner)
        where T : class
    {
        return _asyncLockOwnership.Transfer(_owner, owner);
    }

    /// <summary>
    /// Release the AsyncLockWithOwner(semaphore) if this owner is the current owner.
    /// Calling a second time with the same this owner will do nothing and return false.
    /// </summary>
    /// <returns>True if released - this owner is the current owner.</returns>
    public readonly bool Release()
    {
        return _asyncLockOwnership?.Release(_owner) ?? false;
    }

    /// <summary>
    /// Release the AsyncLockWithOwner(semaphore) if this owner is the current owner.
    /// </summary>
    public readonly void Dispose()
    {
        _ = _asyncLockOwnership?.Release(_owner);
    }
}
