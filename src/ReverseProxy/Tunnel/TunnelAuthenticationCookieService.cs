// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace Yarp.ReverseProxy.Tunnel;
public interface ITunnelAuthenticationCookieService
{
    string NewCookie(ClaimsPrincipal principal);

    bool ValidateCookie(string cookie, [MaybeNullWhen(false)] out ClaimsPrincipal principal);
}

public class TunnelAuthenticationCookieService
    : ITunnelAuthenticationCookieService
{
#pragma warning disable IDE0060 // Remove unused parameter
    public static TunnelAuthenticationCookieService Create(IServiceProvider serviceProvider)
#pragma warning restore IDE0060 // Remove unused parameter
    {
        return new TunnelAuthenticationCookieService(GetNow);
    }

    private static DateTimeOffset GetNow() => DateTimeOffset.UtcNow;

    internal record Item(
        ClaimsPrincipal Principal,
        DateTimeOffset TTL
        );

    private readonly ConcurrentDictionary<string, Item> _items = new ConcurrentDictionary<string, Item>(StringComparer.OrdinalIgnoreCase);
    private readonly Func<DateTimeOffset> _getNow;
    private DateTimeOffset _recycleAt;

    public TunnelAuthenticationCookieService(Func<DateTimeOffset> getNow)
    {
        _getNow = getNow;
        _recycleAt = getNow().AddMinutes(10);
    }

    public string NewCookie(ClaimsPrincipal principal)
    {
        var now = _getNow();
        while (true)
        {
            var result = Guid.NewGuid().ToString("N");
            var item = new Item(principal, now.AddSeconds(30));
            if (_items.TryAdd(result, item))
            {
                return result;
            }
        }
    }

    public bool ValidateCookie(string cookie, [MaybeNullWhen(false)] out ClaimsPrincipal principal)
    {
        var now = _getNow();
        if (_recycleAt < now)
        {
            _recycleAt = now.AddMinutes(10);
            foreach (var kv in _items)
            {
                if (kv.Value.TTL < now)
                {
                    _items.TryRemove(kv.Key, out _);
                }
            }
        }
        if (_items.TryGetValue(cookie, out var item)
            && now < item.TTL)
        {
            principal = item.Principal;
            return true;
        }
        {
            principal = default;
            return false;
        }
    }
}
