// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Extension methods for <see cref="X509Certificate2"/>.
/// </summary>
public static class X509Certificate2Extensions
{
    /// <summary>
    /// Determines if the certificate is self signed.
    /// </summary>
    /// <param name="certificate">The <see cref="X509Certificate2"/>.</param>
    /// <returns>True if the certificate is self signed.</returns>
    public static bool IsSelfSigned2(this X509Certificate2 certificate)
    {

#if NET8_0_OR_GREATER
        Span<byte> subject = certificate.SubjectName.RawData;
        Span<byte> issuer = certificate.IssuerName.RawData;
        return subject.SequenceEqual(issuer);
#else
        var subject = certificate.SubjectName.RawData;
        var issuer = certificate.IssuerName.RawData;
        return subject.SequenceEqual(issuer);
#endif
    }
}
