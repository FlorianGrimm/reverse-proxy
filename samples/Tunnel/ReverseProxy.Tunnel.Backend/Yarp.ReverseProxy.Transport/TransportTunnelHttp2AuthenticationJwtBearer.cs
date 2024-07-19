using System;
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
    private IAccount? _account;

    public TransportTunnelHttp2AuthenticationJwtBearer(
        IOptions<Microsoft.Identity.Client.ConfidentialClientApplicationOptions> options
        )
    {
        _options = options.Value;
        _confidentialClientApplication = Microsoft.Identity.Client.ConfidentialClientApplicationBuilder
            .CreateWithApplicationOptions(_options)
            .Build();
    }

    public string GetAuthenticationName() => "JwtBearer";

    public ValueTask<HttpMessageInvoker?> ConfigureSocketsHttpHandlerAsync(TunnelState tunnel, SocketsHttpHandler socketsHttpHandler)
        => ValueTask.FromResult<HttpMessageInvoker?>(null);

    public async ValueTask ConfigureHttpRequestMessageAsync(TunnelState tunnel, HttpRequestMessage requestMessage)
    {
        // is a quick AcquireTokenSilent possible?
        if (_account is { }) {
            try
            {
                var authenticationResult = await _confidentialClientApplication.AcquireTokenSilent([], _account).ExecuteAsync();
                requestMessage.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());
                return;
            }
            catch
            {
            }
        }

        // do the full AcquireTokenForClient
        {
            var authenticationResult = await _confidentialClientApplication.AcquireTokenForClient(new string[] { ".default" }).ExecuteAsync();
            requestMessage.Headers.Add("Authorization", authenticationResult.CreateAuthorizationHeader());
            _account = authenticationResult.Account;
        }
    }
}
