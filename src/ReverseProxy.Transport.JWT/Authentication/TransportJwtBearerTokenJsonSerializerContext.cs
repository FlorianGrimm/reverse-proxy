// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.DependencyInjection;

using System.Text.Json.Serialization;

namespace Yarp.ReverseProxy.Authentication;

[JsonSerializable(typeof(TransportJwtBearerTokenOptions))]
internal sealed partial class TransportJwtBearerTokenJsonSerializerContext : JsonSerializerContext
{
}
