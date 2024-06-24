using System;
using System.Threading;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Utilities;

public class AsyncLockWithOwner : IDisposable
{
    private SemaphoreSlim _semaphore;

    public AsyncLockWithOwner(int maximum)
    {
        _semaphore = new SemaphoreSlim(maximum);
    }

    public bool IsDisposed { get; private set; }

    public async ValueTask<AsyncLockOwner> LockAsync(object? owner, CancellationToken cancellationToken)
    {
        await _semaphore.WaitAsync(cancellationToken);
        return AsyncLockOwnership.Create(owner, this);
    }

    internal void Release()
    {
        _semaphore.Release();
    }

    protected virtual void Dispose(bool disposing)
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

public sealed class AsyncLockOwnership
{
    private static readonly object _notAOwner = new();
    public static AsyncLockOwner Create<T>(T? owner, AsyncLockWithOwner asyncLockWithOwner)
        where T : class
    {
        var asyncLockOwnership = new AsyncLockOwnership(owner, asyncLockWithOwner);
        return new AsyncLockOwner(asyncLockOwnership, owner);
    }

    private object? _owner;
    private readonly AsyncLockWithOwner _asyncLockWithOwner;

    private AsyncLockOwnership(object? owner, AsyncLockWithOwner asyncLockWithOwner)
    {
        _owner = owner;
        _asyncLockWithOwner = asyncLockWithOwner;
    }

    internal bool Release<T>(T? owner)
        where T : class
    {
        if (ReferenceEquals(
            owner,
            System.Threading.Interlocked.CompareExchange(ref _owner, _notAOwner, owner)))
        {
            _asyncLockWithOwner.Release();
            return true;
        }
        else
        {
            return false;
        }
    }

    internal AsyncLockOwner Transfer<T>(T? owner)
        where T : class
    {
        System.Threading.Interlocked.Exchange(ref _owner, _notAOwner);
        return new AsyncLockOwner(this, owner);
    }
}

public struct AsyncLockOwner : IDisposable
{
    private readonly AsyncLockOwnership _asyncLockOwnership;
    private readonly object? _owner;

    internal AsyncLockOwner(AsyncLockOwnership asyncLockOwnership, object? owner)
    {
        _asyncLockOwnership = asyncLockOwnership;
        _owner = owner;
    }

    public AsyncLockOwner Transfer(object owner)
    {
        return _asyncLockOwnership.Transfer(owner);
    }

    public bool Release()
    {
        return _asyncLockOwnership?.Release(_owner) ?? false;
    }

    public void Dispose()
    {
        _asyncLockOwnership?.Release(_owner);
    }
}
