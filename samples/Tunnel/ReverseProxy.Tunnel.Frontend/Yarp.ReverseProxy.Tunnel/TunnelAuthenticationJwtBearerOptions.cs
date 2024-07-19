namespace Yarp.ReverseProxy.Tunnel;

internal class TunnelAuthenticationJwtBearerOptions {
    public string? TenantId { get;set }
    public string? ClientId { get;set }
    public string? Audience { get; set }
}
