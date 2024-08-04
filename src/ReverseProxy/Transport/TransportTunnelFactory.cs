using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;

public interface ITransportTunnelFactory
{
    string GetTransport();
    void Listen(TunnelState tunnel, Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions options);
}

public sealed class TransportTunnelFactory
{
    private readonly ImmutableDictionary<string, ITransportTunnelFactory> _TransportTunnelFactoryByTransport;

    public TransportTunnelFactory(
        IEnumerable<ITransportTunnelFactory> listTransportTunnelFactory
        )
    {
        var dict = new Dictionary<string, ITransportTunnelFactory>(StringComparer.OrdinalIgnoreCase);
        foreach (var transportTunnelFactory in listTransportTunnelFactory) {
            dict[transportTunnelFactory.GetTransport()] = transportTunnelFactory;
        }
        _TransportTunnelFactoryByTransport = dict.ToImmutableDictionary(StringComparer.OrdinalIgnoreCase);
    }

    public bool TryGetTransportTunnelFactory(string transport, [MaybeNullWhen(false)] out ITransportTunnelFactory transportTunnelFactory) {
        return _TransportTunnelFactoryByTransport.TryGetValue(transport, out transportTunnelFactory);
    }
}

internal class TransportTunnelHttp2Factory : ITransportTunnelFactory
{
    private readonly TransportTunnelHttp2Options _options;
    private readonly TransportTunnelHttp2Authentication _transportTunnelHttp2Authentication;
    private readonly List<string> _ListAuthenticationNameH2;

    public TransportTunnelHttp2Factory(
        IOptions<TransportTunnelHttp2Options> options,
        TransportTunnelHttp2Authentication transportTunnelHttp2Authentication
        )
    {
        _options = options.Value;
        _transportTunnelHttp2Authentication = transportTunnelHttp2Authentication;
        _ListAuthenticationNameH2 = _transportTunnelHttp2Authentication.GetAuthenticationNames();
    }
    public string GetTransport() => "TunnelHttp2";

    public void Listen(TunnelState tunnel, KestrelServerOptions options)
    {
        if (!_options.IsEnabled)
        {
            throw new NotSupportedException($"Tunnel HTTP2 is disabled.");
        }

        var cfg = tunnel.Model.Config;
        var remoteTunnelId = cfg.GetRemoteTunnelId();
        var host = cfg.Url.TrimEnd('/');
        var cfgAuthenticationMode = cfg.Authentication.Mode;
        if (_ListAuthenticationNameH2.FirstOrDefault(n => string.Equals(n, cfgAuthenticationMode)) is { } authenticationMode)
        {
            var uriTunnel = new Uri($"{host}/_Tunnel/H2/{authenticationMode}/{remoteTunnelId}", UriKind.Absolute);
            options.Listen(new UriEndPointHttp2(uriTunnel, tunnel.TunnelId));
            return;
        }
        else
        {
            throw new NotSupportedException($"Authentication {cfgAuthenticationMode} is unknown");
        }
    }
}
internal class TransportTunnelWebSocketFactory : ITransportTunnelFactory
{
    private readonly TransportTunnelWebSocketOptions _options;
    private readonly TransportTunnelWebSocketAuthentication _transportTunnelWebSocketAuthentication;
    private readonly List<string> _listAuthenticationNameWS;

    public TransportTunnelWebSocketFactory(
        IOptions<TransportTunnelWebSocketOptions> options,
        TransportTunnelWebSocketAuthentication transportTunnelWebSocketAuthentication
        )
    {
        _options = options.Value;
        _transportTunnelWebSocketAuthentication = transportTunnelWebSocketAuthentication;
        _listAuthenticationNameWS = transportTunnelWebSocketAuthentication.GetAuthenticationNames();
    }
    public string GetTransport() => "TunnelWebSocket";

    public void Listen(TunnelState tunnel, KestrelServerOptions options)
    {
        if (!_options.IsEnabled)
        {
            throw new NotSupportedException($"Tunnel WebSocket is disabled.");
        }
        var cfg = tunnel.Model.Config;
        var remoteTunnelId = cfg.GetRemoteTunnelId();
        var host = cfg.Url.TrimEnd('/');

        var cfgAuthenticationMode = cfg.Authentication.Mode;
        if (_listAuthenticationNameWS.FirstOrDefault(n => string.Equals(n, cfgAuthenticationMode)) is { } authenticationMode)
        {
            var uriTunnel = new Uri($"{host}/_Tunnel/WS/{authenticationMode}/{remoteTunnelId}", UriKind.Absolute);
            options.Listen(new UriWebSocketEndPoint(uriTunnel, tunnel.TunnelId));
            return;
        }
        else
        {
            throw new NotSupportedException($"Authentication {cfgAuthenticationMode} is unknown");
        }
    }
}

