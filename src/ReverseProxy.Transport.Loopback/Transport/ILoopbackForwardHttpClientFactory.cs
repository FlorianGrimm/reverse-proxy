using System.Net.Http;

namespace Yarp.ReverseProxy.Transport;

public interface ILoopbackForwardHttpClientFactory
{
    HttpClient CreateHttpClient();
}
