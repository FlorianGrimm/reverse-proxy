using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using Yarp.ReverseProxy.Configuration;

namespace Yarp.ReverseProxy.Tunnel;

public interface ITunnelAuthenticationConfigService
{
    bool Configure(SocketsHttpHandler socketsHttpHandler, TunnelAuthenticationConfig authentication);
}
