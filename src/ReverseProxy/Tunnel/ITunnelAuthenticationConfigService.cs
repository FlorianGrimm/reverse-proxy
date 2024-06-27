// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace Yarp.ReverseProxy.Tunnel;

public interface ITunnelAuthenticationConfigService
{
#warning WEICHEI guess this is wrong
    //bool Configure(SocketsHttpHandler socketsHttpHandler, TunnelAuthenticationConfig authentication);

    void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions);
}
