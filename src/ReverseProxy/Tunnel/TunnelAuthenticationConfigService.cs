// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;

using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationConfigService
    : ITunnelAuthenticationConfigService
{
    private readonly List<ITunnelAuthenticationConfigService> _services;

    public TunnelAuthenticationConfigService(
        IEnumerable<ITunnelAuthenticationConfigService> listTunnelAuthenticationConfigService)
    {
        _services = listTunnelAuthenticationConfigService.ToList();
    }

#warning WEICHEI
    //public bool Configure(SocketsHttpHandler socketsHttpHandler, TunnelAuthenticationConfig authentication)
    //{
    //    foreach (var service in _services)
    //    {
    //        if (service.Configure(socketsHttpHandler, authentication))
    //        {
    //            return true;
    //        }
    //    }
    //    return false;
    //}

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        foreach (var service in _services)
        {
            service.ConfigureKestrelServer(kestrelServerOptions);
        }
    }


}
