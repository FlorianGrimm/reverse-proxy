// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NET8_0_OR_GREATER
using Microsoft.AspNetCore.Authentication;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System;

using Microsoft.AspNetCore.Http.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Authentication;

namespace Microsoft.Extensions.DependencyInjection;

public class TransportJwtBearerTokenConfigureJsonOptions : IConfigureOptions<JsonOptions>
{
    public void Configure(JsonOptions options)
    {
        // Put our resolver in front of the reflection-based one. See ProblemDetailsOptionsSetup for a detailed explanation.
        options.SerializerOptions.TypeInfoResolverChain.Insert(0, TransportJwtBearerTokenJsonSerializerContext.Default);
    }
}
#endif
