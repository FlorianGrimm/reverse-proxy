namespace Yarp.ReverseProxy.Model;

/// <summary>
/// Listener for changes in the tunnels.
/// </summary>
public interface ITunnelChangeListener
{
    /// <summary>
    /// Gets called after a new <see cref="TunnelState"/> has been added.
    /// </summary>
    /// <param name="tunnel">Added <see cref="TunnelState"/> instance.</param>
    void OnTunnelAdded(TunnelState tunnel);

    /// <summary>
    /// Gets called after an existing <see cref="TunnelState"/> has been changed.
    /// </summary>
    /// <param name="tunnel">Changed <see cref="TunnelState"/> instance.</param>
    void OnTunnelChanged(TunnelState tunnel);

    /// <summary>
    /// Gets called after an existing <see cref="TunnelState"/> has been removed.
    /// </summary>
    /// <param name="tunnel">Removed <see cref="TunnelState"/> instance.</param>
    void OnTunnelRemoved(TunnelState tunnel);
}
