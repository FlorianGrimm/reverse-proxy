using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Tunnel;
public class TunnelBackendOptions
{
    public int MaxConnectionCount { get; set; } = 10;
}
