#pragma warning disable xUnit2004 // Do not use equality check to test for boolean conditions
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace Yarp.ReverseProxy.Utilities;

public class AsyncLockWithOwnerTests
{
    [Fact]
    public async Task LockAndRelease()
    {
        var asyncLockWithOwner = new AsyncLockWithOwner(10);
        Assert.Equal(10, asyncLockWithOwner.CurrentCount);

        var obj1 = "1";
        var obj2 = "2";

        var l1 = await asyncLockWithOwner.LockAsync(obj1, CancellationToken.None);
        Assert.Equal(9, asyncLockWithOwner.CurrentCount);

        var l2 = await asyncLockWithOwner.LockAsync(obj2, CancellationToken.None);
        Assert.Equal(8, asyncLockWithOwner.CurrentCount);

        Assert.Equal(true, l1.Release());
        Assert.Equal(9, asyncLockWithOwner.CurrentCount);

        Assert.Equal(true, l2.Release());
        Assert.Equal(10, asyncLockWithOwner.CurrentCount);
    }

    [Fact]
    public async Task LockTransferAndRelease()
    {
        var asyncLockWithOwner = new AsyncLockWithOwner(10);
        Assert.Equal(10, asyncLockWithOwner.CurrentCount);

        var obj1 = "1";
        var obj2 = "2";

        var l1 = await asyncLockWithOwner.LockAsync(obj1, CancellationToken.None);
        Assert.Equal(9, asyncLockWithOwner.CurrentCount);

        var l2 = l1.Transfer(obj2);

        Assert.Equal(false, l1.Release());
        Assert.Equal(9, asyncLockWithOwner.CurrentCount);

        Assert.Equal(true, l2.Release());
        Assert.Equal(10, asyncLockWithOwner.CurrentCount);
    }


}
