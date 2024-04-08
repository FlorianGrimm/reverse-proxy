namespace Yarp.ReverseProxy.Tunnel.Backwarder;

internal interface ICloseable
{
    bool IsClosed { get; }
    void Abort();
}
