// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable xUnit2013 // Do not use equality check to check for collection size.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace Yarp.ReverseProxy.Utilities.Tests;
public class AsyncLockWithOwnerTests
{
    [Fact]
    public async Task AsyncLockWithOwnerMaximum()
    {
        var maximum = 10;
        var count = maximum * 10;
        var rng = new Random(0); // pseudo-random, jund of reproducibility
        var cts = new CancellationTokenSource();
        var sut = new AsyncLockWithOwner(maximum);
        var lst = Enumerable.Range(0, count).Select((index) =>
        {
            var owner = new object();
            return new {
                index = index,
                owner = owner,
                task = sut.LockAsync(owner, cts.Token).AsTask()
            };
        }).ToList();

        for (var loop = 0;
            (loop < 100) && (0 < lst.Count);
            loop++)
        {
            var cnt = lst.Count(i => (i.task.IsCompleted));
            Assert.True(cnt <= maximum);

            if (0 < cnt)
            {
                for (var index = lst.Count - 1; 0 <= index; index--)
                {
                    var item = lst[index];
                    if (item.task.IsCompleted)
                    {
                        if (rng.Next(count) == 0)
                        {
                            break;
                        }
                        var asyncLockOwner = await item.task;
                        asyncLockOwner.Release();
                        lst.RemoveAt(index);
                    }
                }
            }
            await Task.Delay(rng.Next(maximum));
        }
        Assert.Equal(0, lst.Count);
    }

    [Fact]
    public async Task AsyncLockWithOwnerTransferThenRelease()
    {
        var maximum = 10;
        var count = maximum * 10;
        var rng = new Random(0); // pseudo-random reproducibility
        var cts = new CancellationTokenSource();
        var sut = new AsyncLockWithOwner(maximum);

        var owner1 = new object();
        var owner2 = new object();
        var owner3 = new object();
        var asyncLockOwner1 = await sut.LockAsync(owner1, cts.Token);
        var asyncLockOwner2 = asyncLockOwner1.Transfer(owner2);
        var asyncLockOwner3 = asyncLockOwner2.Transfer(owner3);
        var result1 = asyncLockOwner1.Release();
        var result2 = asyncLockOwner2.Release();
        var result3 = asyncLockOwner3.Release();
        Assert.False(result1);
        Assert.False(result2);
        Assert.True(result3);
    }

    [Fact]
    public async Task AsyncLockWithOwnerReleaseThenTransfer()
    {
        var maximum = 10;
        var count = maximum * 10;
        var rng = new Random(0); // pseudo-random reproducibility
        var cts = new CancellationTokenSource();
        var sut = new AsyncLockWithOwner(maximum);

        var owner1 = new object();
        var owner2 = new object();
        var owner3 = new object();
        var asyncLockOwner1 = await sut.LockAsync(owner1, cts.Token);
        Assert.True(asyncLockOwner1.HasOwner());
        var result1 = asyncLockOwner1.Release();
        var asyncLockOwner2 = asyncLockOwner1.Transfer(owner2);
        Assert.False(asyncLockOwner2.HasOwner());
        var asyncLockOwner3 = asyncLockOwner2.Transfer(owner3);
        var result2 = asyncLockOwner2.Release();
        var result3 = asyncLockOwner3.Release();
        Assert.True(result1);
        Assert.False(result3);
        Assert.False(result2);
    }

    [Fact]
    public async Task AsyncLockWithOwnerTransferThenReleaseThenTransfer()
    {
        var maximum = 10;
        var count = maximum * 10;
        var rng = new Random(0); // pseudo-random reproducibility
        var cts = new CancellationTokenSource();
        var sut = new AsyncLockWithOwner(maximum);

        var owner1 = new object();
        var owner2 = new object();
        var owner3 = new object();
        var asyncLockOwner1 = await sut.LockAsync(owner1, cts.Token);
        var asyncLockOwner2 = asyncLockOwner1.Transfer(owner2);
        var result1 = asyncLockOwner1.Release();
        var result2 = asyncLockOwner2.Release();
        var asyncLockOwner3 = asyncLockOwner2.Transfer(owner3);
        var result3 = asyncLockOwner3.Release();
        Assert.False(result1);
        Assert.True(result2);
        Assert.False(result3);
    }
}
