// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Extensions.Primitives;

namespace Microsoft.AspNetCore.Http;

public static class TransportJwtBearerUtility
{
    private const string PrefixBearer = "Bearer ";

    /// <summary>
    /// Get the bearer token from the Authorization header.
    /// </summary>
    /// <param name="authorization">The authorization header.</param>
    /// <returns>the bearer token</returns>
    public static string? GetBearerToken(StringValues authorization)
    {
        foreach (var valueAuthorization in authorization)
        {
            if (valueAuthorization is { Length: > 7 }
                && valueAuthorization.StartsWith(PrefixBearer))
            {
                return valueAuthorization.Substring(PrefixBearer.Length);
            }
        }
        return null;
    }
}
