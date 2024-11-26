// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelCertificateConstants
{
    /// <summary>
    /// "ClientCertificate"
    /// </summary>
    public const string AuthenticationName = "ClientCertificate";

    /// <summary>
    /// "Certificate"
    /// </summary>
    public const string AuthenticationScheme = "Certificate";

    /// <summary>
    /// "YarpTunnelAuth"
    /// </summary>
    public const string CookieName = "YarpTunnelAuth";
}
