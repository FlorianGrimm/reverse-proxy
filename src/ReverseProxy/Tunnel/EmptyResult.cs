// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

namespace Yarp.ReverseProxy.Tunnel;

// This is for .NET 6, .NET 7 has Results.Empty
internal sealed class EmptyResult : IResult
{
    internal static readonly EmptyResult Instance = new();

    public Task ExecuteAsync(HttpContext httpContext)
    {
        return Task.CompletedTask;
    }
}
