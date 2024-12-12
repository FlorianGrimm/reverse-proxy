// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelNegotiateConstants {
    public const string PolicyNameGetAuth = "YarpTunnelNegotiateGetAuth";
    public const string PolicyNamePayload = "YarpTunnelNegotiatePayload";
    //public const string NegotiateAuthenticationName = "Negotiate";
    public const string NegotiateAuthenticationName = Microsoft.AspNetCore.Authentication.Negotiate.NegotiateDefaults.AuthenticationScheme;
    public const string CookieName = "YarpTunnelAuth";
}
