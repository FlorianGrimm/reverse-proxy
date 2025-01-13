using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

using Xunit;

namespace Yarp.ReverseProxy.Tunnel;
public class FileName
{
    [Fact]
    public void Method()
    {
        var fnA1 = MethodA(1);
        var fnA2 = MethodA(2);

        var fnB1 = MethodB(1);
        var fnB2 = MethodB(2);

        Assert.Equal(2, fnA1(1));
        Assert.Equal(3, fnA2(1));

        Assert.Equal(4, fnB1(3));
        Assert.Equal(5, fnB2(3));
    }

    private Func<int, int> MethodA(int a)
    {
        return fn;

        int fn(int b) {
            return a + b;
        }
    }

    private Func<int, int> MethodB(int a)
    {
        var a2 = a;
        return fn;

        int fn(int b)
        {
            return a2 + b;
        }
    }
}
