
using Microsoft.AspNetCore.Connections.Features;

using Yarp.ReverseProxy.Transport;

namespace ReverseProxy.Tunnel;

public class HttpRequestDump
{
    public HttpRequestDump() { }
    public HttpRequestDump(
        string Protocol,
        string Method,
        string Scheme,
        string? Host,
        string? PathBase,
        string? Path,
        string? Query,
        Dictionary<string, string?[]> Headers,
        DateTimeOffset Time,
        string? TransportMode,
        bool? UserIsAuthenticated,
        string? UserName,
        IEnumerable<object> UserClaims,
        string Body)
    {
        this.Protocol = Protocol;
        this.Method = Method;
        this.Scheme = Scheme;
        this.Host = Host;
        this.PathBase = PathBase;
        this.Path = Path;
        this.Query = Query;
        this.Headers = Headers;
        this.Time = Time;
        this.TransportMode = TransportMode;
        this.UserIsAuthenticated = UserIsAuthenticated;
        this.UserName = UserName;
        this.UserClaims = UserClaims;
        this.Body = Body;
    }

    public string Protocol { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public string Scheme { get; set; } = string.Empty;
    public string? Host { get; set; }
    public string? PathBase { get; set; }
    public string? Path { get; set; }
    public string? Query { get; set; }
    public Dictionary<string, string?[]> Headers { get; set; } = new();
    public DateTimeOffset Time { get; set; }
    public string? TransportMode { get; set; }
    public bool? UserIsAuthenticated { get; set; }
    public string? UserName { get; set; }
    public IEnumerable<object> UserClaims { get; set; } = [];
    public string Body { get; set; } = string.Empty;

    public static async Task<HttpRequestDump> GetDumpAsync(HttpContext httpContext, HttpRequest httpRequest, bool readBody)
    {
        var transportMode = (httpContext.Features.Get<IConnectionItemsFeature>()?.Items is { } items
            && items.TryGetValue(typeof(IConnectionTransportTunnelFeature), out var objValue)
            && objValue is IConnectionTransportTunnelFeature feature) ? feature.TransportMode : default(string?);

        var body = readBody ? (await new StreamReader(httpRequest.Body).ReadToEndAsync()) : string.Empty;
        var result = new HttpRequestDump(
            Protocol: httpRequest.Protocol,
            Method: httpRequest.Method,
            Scheme: httpRequest.Scheme,
            Host: httpRequest.Host.Value,
            PathBase: httpRequest.PathBase.Value,
            Path: httpRequest.Path.Value,
            Query: httpRequest.QueryString.Value,
            Headers: httpRequest.Headers.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToArray()),
            Time: DateTimeOffset.UtcNow,
            TransportMode: transportMode,
            UserIsAuthenticated: httpContext.User.Identity?.IsAuthenticated,
            UserName: httpContext.User.Identity?.Name,
            UserClaims: httpContext.User.Claims.Select(claim => new { Type = claim.Type, Value = claim.Value }),
            Body: body
        );
        return result;
    }

}
