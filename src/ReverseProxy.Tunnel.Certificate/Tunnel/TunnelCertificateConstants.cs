// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Yarp.ReverseProxy.Tunnel;

public class TunnelCertificateConstants
{
    /// <summary>
    /// "ClientCertificate"
    /// </summary>
    public const string AuthenticationName = "ClientCertificate";


    //public const string AuthenticationScheme = "Certificate";

    /// <summary>
    /// "Certificate"
    /// </summary>
    public const string AuthenticationScheme = "TunnelClientCertificate";

    /// <summary>
    /// "YarpTunnelAuth"
    /// </summary>
    public const string CookieName = "YarpTunnelAuth";

    public const string PolicyName = "YarpTunnelClientCertificate";
}
