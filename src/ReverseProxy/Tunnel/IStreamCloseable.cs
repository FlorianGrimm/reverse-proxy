/// <summary>
/// Represents an interface for a stream that can be closed.
/// </summary>
public interface IStreamCloseable
{
    /// <summary>
    /// Gets a value indicating whether the stream is closed.
    /// </summary>
    bool IsClosed { get; }

    /// <summary>
    /// Aborts the stream.
    /// </summary>
    void Abort();
}
