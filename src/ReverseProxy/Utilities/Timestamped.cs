using System;

namespace Yarp.ReverseProxy.Utilities;

internal record struct Timestamped<T>(T Value, DateTimeOffset Timestamp);
