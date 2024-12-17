// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Utilities;

public interface IAsyncLockWithOwner
{
    void Release();
}

/// <summary>
/// Async Semaphore the WaitAsync is only allowed for a maximum times.
/// Also the WaitAsync need an owner, that can be transfered to another owner.
/// Only if latest owner release it's acutal released.
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

    internal int CurrentCount => _semaphore.CurrentCount;

    public bool IsDisposed { get; private set; }

    public async ValueTask<AsyncLockOwner> LockAsync(object? owner, CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken);
        return AsyncLockOwnership.Create(owner, this);
    }

    void IAsyncLockWithOwner.Release()
    {
        _semaphore.Release();
    }

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

public interface IAsyncLockOwnership
{
    AsyncLockOwner Transfer<T>(object? oldOwner, T? owner) where T : class;

    bool Release<T>(T? owner) where T : class;
}

/// <summary>
/// One semiphore count/step with an owner.
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

    AsyncLockOwner IAsyncLockOwnership.Transfer<T>(object? oldOwner, T? owner)
        where T : class
    {
        System.Threading.Interlocked.CompareExchange(ref _owner, owner, oldOwner);
        return new AsyncLockOwner(this, owner);
    }
}

/// <summary>
/// 
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

    public AsyncLockOwner Transfer<T>(T? owner)
        where T : class
    {
        return _asyncLockOwnership.Transfer(_owner, owner);
    }

    public readonly bool Release()
    {
        return _asyncLockOwnership?.Release(_owner) ?? false;
    }

    public readonly void Dispose()
    {
        _ = _asyncLockOwnership?.Release(_owner);
    }
}
