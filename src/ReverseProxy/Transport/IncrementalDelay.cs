// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Transport;

internal sealed class IncrementalDelay(
    int increment = 500,
    int maximum = 15 * 60 * 1000,
    int limitWarning = 60 * 1000)
{
    internal int Increment = increment;
    internal int Maximum = maximum;
    internal int Current = 0;
    internal int LimitWarning = limitWarning;
    private int _CountWait = 0;

    public bool Reset()
    {
        if (0 == Current)
        {
            return false;
        }
        else if (Current < LimitWarning)
        {
            Current = 0;
            return false;
        }
        else
        {
            Current = 0;
            return true;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public async ValueTask Delay(CancellationToken cancellationToken)
    {
        System.Threading.Interlocked.Increment(ref _CountWait);
        try
        {
            await Task.Delay(Current, cancellationToken);
        }
        finally
        {
            System.Threading.Interlocked.Decrement(ref _CountWait);
        }
    }

    public bool IncrementDelay()
    {
        bool raiseWarning;
        if (Current < Maximum)
        {
            var belowLimit = Current < LimitWarning;
            Current += (Increment / (_CountWait + 1));
            if (Maximum < Current) { Current = Maximum; }
            raiseWarning = belowLimit && (LimitWarning <= Current);
        }
        else
        {
            raiseWarning = false;
        }

        return raiseWarning;
    }
}
