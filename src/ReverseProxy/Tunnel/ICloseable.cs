// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Tunnel
{
    internal interface ICloseable
    {
        bool IsClosed { get; }
        void Abort();
    }
}
