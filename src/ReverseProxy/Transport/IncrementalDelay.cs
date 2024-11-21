// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Transport;

/// <summary>
/// Delay incremented the timespan each time.
/// </summary>
public class IncrementalDelay
{
    protected int _increment;
    protected int _maximum;
    protected int _current;
    
    public IncrementalDelay()
    {
        _increment = 500;
        _maximum = 60 * 1000;
        _current = 0;
    }

    /// <summary>
    /// Reset the delay;
    /// </summary>
    /// <returns>true if Delay-ed before.</returns>
    public bool Reset()
    {
        if (0 == _current)
        {
            return false;
        }
        else
        {
            _current = 0;
            return true;
        }
    }

    /// <summary>
    /// Wait for a while.
    /// </summary>
    /// <param name="cancellationToken">stop me</param>
    /// <returns>async future</returns>
    public virtual async ValueTask Delay(CancellationToken cancellationToken)
    {
        var current = _current;
        var next = current + _increment;
        if (_maximum <= next) { next = _maximum; }
        System.Threading.Interlocked.CompareExchange(ref _current, next, current);

        await Task.Delay(next, cancellationToken);

    }
}
