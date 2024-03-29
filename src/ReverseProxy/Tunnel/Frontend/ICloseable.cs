namespace Yarp.ReverseProxy.Tunnel.Frontend;

internal interface ICloseable
{
    bool IsClosed { get; }
    void Abort();
}
