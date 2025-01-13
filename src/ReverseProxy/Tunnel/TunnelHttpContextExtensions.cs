// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Http;

/// <summary>
/// extensions for HttpContext
/// </summary>
public static class TunnelHttpContextExtensions
{
    private const string HeaderXForwardedHost = "x-forwarded-host";

    /// <summary>
    /// Check if the request is (better might be) forwarded aka if the x-forwarded-host header is present.
    /// </summary>
    /// <param name="httpContext">The current context</param>
    /// <returns>the x-forwarded-host header is present</returns>
    /// <remarks>This helps to deicide which authentication schema should be used. It does not provide any evidence.</remarks>
    public static bool IsXForwardedHostRequest(this HttpContext? httpContext)
    {
        if (httpContext is null) { return false; }

        {
            foreach (var xForwardedHost in httpContext.Request.Headers[HeaderXForwardedHost])
            {
                if (xForwardedHost is { Length: > 0 })
                {
                    return true;
                }
            }
        }
        return false;
    }
}
