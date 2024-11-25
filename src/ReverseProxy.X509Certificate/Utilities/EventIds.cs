// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace Yarp.ReverseProxy;

internal static class EventIds
{
    
    public static readonly EventId SuccessfullyLoadedCertificate = new EventId(100, "SuccessfullyLoadedCertificate");
    public static readonly EventId MissingOrInvalidCertificateFile = new EventId(101, "MissingOrInvalidCertificateFile");
    public static readonly EventId MissingOrInvalidCertificateKeyFile = new EventId(102, "MissingOrInvalidCertificateKeyFile");
    public static readonly EventId SuccessfullyLoadedCertificateKey = new EventId(103, "SuccessfullyLoadedCertificateKey");
    public static readonly EventId CertificatePathIsNotFullyQualified = new EventId(104, "CertificatePathIsNotFullyQualified");

    public static readonly EventId SuccessfullyLoadedCertificateBySubject = new EventId(105, "SuccessfullyLoadedCertificateBySubject");
    public static readonly EventId NoCertificateFoundBySubject = new EventId(106, "NoCertificateFoundBySubject");
}
