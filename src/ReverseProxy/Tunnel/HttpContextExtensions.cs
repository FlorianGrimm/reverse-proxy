using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Yarp.ReverseProxy.Tunnel;

public static class HttpContextExtensions
{
    private const string PrefixBearer = "Bearer ";
    private const string HeaderXForwardedHost = "x-forwarded-host";

    public static bool IsForwardedRequest(this HttpContext? httpContext)
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

    public static bool IsForwardedBearerAuthentication(this HttpContext? httpContext)
    {
        if (httpContext is null) { return false; }

        {
            var foundForwardedHosts = false;
            foreach (var xForwardedHost in httpContext.Request.Headers[HeaderXForwardedHost])
            {
                if (xForwardedHost is { Length: > 0 })
                {
                    foundForwardedHosts = true;
                    break;
                }
            }

            if (foundForwardedHosts)
            {
                foreach (var valueAuthorization in httpContext.Request.Headers.Authorization)
                {
                    if (valueAuthorization is { Length: > 7 }
                        && valueAuthorization.StartsWith(PrefixBearer))
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }


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
