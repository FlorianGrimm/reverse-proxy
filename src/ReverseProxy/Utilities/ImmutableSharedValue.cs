namespace Yarp.ReverseProxy.Utilities;

public sealed class ImmutableSharedValue<T> : ISharedValue<T?>
    where T : class
{
    public ImmutableSharedValue(T value)
    {
        Value = value;
    }
    public T? Value { get; }

    public T? GiveAway() => Value;

    public void Dispose() { }
}
