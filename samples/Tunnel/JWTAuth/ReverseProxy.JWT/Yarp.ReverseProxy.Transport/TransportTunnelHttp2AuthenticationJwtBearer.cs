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
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _asyncLock = new SemaphoreSlim(1, 1);
    private IAccount? _account;

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

        try
        {
            var clientId = _options.ClientId;
            var url = tunnel.Model.Config.Url;
            var scopes = new string[] { $"api://{clientId}/.default" };

            await _asyncLock.WaitAsync();
            try
            {
                // is a quick AcquireTokenSilent possible?
                if (_account is { })
                {
                    try
                    {
                        var authenticationResult = await _confidentialClientApplication.AcquireTokenSilent(scopes, _account).ExecuteAsync();
                        requestMessage.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());
                        // _logger.LogTrace($"AcquireTokenSilent for {url} succeeded");
                        return;
                    }
                    catch
                    {
                    }
                }

                // do the full AcquireTokenForClient
                {
                    var authenticationResult = await _confidentialClientApplication.AcquireTokenForClient(scopes).ExecuteAsync();
                    requestMessage.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());
                    _account = authenticationResult.Account;
                    // _logger.LogTrace($"AcquireTokenForClient for {url} succeeded");
                }
            }
            finally
            {
                _asyncLock.Release();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to acquire token for {url}", tunnel.Model.Config.Url);
            throw;
        }
    }
}

