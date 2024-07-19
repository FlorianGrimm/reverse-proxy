using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;

using Yarp.ReverseProxy.Model;

namespace Yarp.ReverseProxy.Transport;
internal class TransportTunnelHttp2AuthenticationJwtBearer
    : ITransportTunnelHttp2Authentication
{
    private readonly ConfidentialClientApplicationOptions _options;
    private readonly IConfidentialClientApplication _confidentialClientApplication;
    private readonly ConcurrentDictionary<string, Item> _accountByUrl = new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger _logger;

    public TransportTunnelHttp2AuthenticationJwtBearer(
        IOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions> options,
        ILogger<TransportTunnelHttp2AuthenticationJwtBearer> logger
        )
    {
        _options = options.Value;
        _confidentialClientApplication = Microsoft.Identity.Client.ConfidentialClientApplicationBuilder
            .CreateWithApplicationOptions(_options)
            .Build();
        _logger = logger;
    }

    public string GetAuthenticationName() => "JwtBearer";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
        => ValueTask.FromResult<HttpMessageInvoker?>(null);

    public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        while (true)
        {
            if (_accountByUrl.TryGetValue(tunnel.Model.Config.Url, out var item))
            {
                await item.ConfigureHttpRequestMessageAsync(tunnel, requestMessage);
                return;
            }
            else
            {
                _accountByUrl.TryAdd(tunnel.Model.Config.Url, new Item(this));
            }
        }
    }
    internal class Item(
        TransportTunnelHttp2AuthenticationJwtBearer owner
        )
    {
        private readonly TransportTunnelHttp2AuthenticationJwtBearer _owner = owner;
        private IAccount? _account;

        public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
        {
            try
            {
                var clientId = _owner._options.ClientId;
                var url = tunnel.Model.Config.Url;
                var scopes = new string[] { $"api://{clientId}/.default" };

                // is a quick AcquireTokenSilent possible?
                if (_account is { })
                {
                    try
                    {
                        var authenticationResult = await _owner._confidentialClientApplication.AcquireTokenSilent(scopes, _account).ExecuteAsync();
                        requestMessage.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());
                        _owner._logger.LogInformation($"AcquireTokenSilent for {url} succeeded");
                        return;
                    }
                    catch
                    {
                    }
                }

                // do the full AcquireTokenForClient
                {
                    var authenticationResult = await _owner._confidentialClientApplication.AcquireTokenForClient(scopes).ExecuteAsync();
                    requestMessage.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());
                    _account = authenticationResult.Account;
                    _owner._logger.LogInformation($"AcquireTokenForClient for {url} succeeded");
                }
            }
            catch (Exception ex)
            {
                _owner._logger.LogError(ex, "Failed to acquire token for {url}", tunnel.Model.Config.Url);
                throw;
            }
        }
    }
}
