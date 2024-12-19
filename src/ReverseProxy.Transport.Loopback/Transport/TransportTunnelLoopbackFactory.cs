using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

internal sealed class TransportTunnelLoopbackFactory : ITransportTunnelFactory
{
    private readonly TransportTunnelLoopbackOptions _options;
    private readonly TransportTunnelLoopbackAuthenticator _authenticator;
    private readonly List<string> _listAuthenticationName;

    public TransportTunnelLoopbackFactory(
        IOptions<TransportTunnelLoopbackOptions> options,
        TransportTunnelLoopbackAuthenticator authenticator
        )
    {
        _options = options.Value;
        _authenticator = authenticator;
        _listAuthenticationName = _authenticator.GetAuthenticationNames();
    }

    public string GetTransport()
        => TransportTunnelLoopbackConstants.TransportNameTunnelLoopback;

    public void Listen(TunnelState tunnel, KestrelServerOptions options)
    {
        if (!_options.IsEnabled)
        {
            throw new NotSupportedException($"Tunnel HTTP2 is disabled.");
        }

        var cfg = tunnel.Model.Config;
        var remoteTunnelId = cfg.GetRemoteTunnelId();
        var host = cfg.Url.TrimEnd('/');
        var cfgAuthenticationMode = cfg.TransportAuthentication.Mode;
        if (_listAuthenticationName.FirstOrDefault(n => string.Equals(n, cfgAuthenticationMode)) is { } authenticationMode)
        {
            var uriTunnel = new Uri($"{host}/_Tunnel/Loopback/{authenticationMode}/{remoteTunnelId}", UriKind.Absolute);
            options.Listen(new LoopbackEndPoint(uriTunnel, tunnel.TunnelId));
            return;
        }
        else
        {
            throw new NotSupportedException($"Authentication {cfgAuthenticationMode} is unknown");
        }
    }
}
