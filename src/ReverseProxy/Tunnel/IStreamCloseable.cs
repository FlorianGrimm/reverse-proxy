namespace Yarp.ReverseProxy.Tunnel;
internal interface IStreamCloseable
{
    bool IsClosed { get; }
    void Abort();
}
