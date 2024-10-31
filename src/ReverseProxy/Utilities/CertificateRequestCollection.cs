using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public sealed class CertificateRequestCollection(
        string id,
        List<CertificateRequest> certificateRequests,
        X509Certificate2Collection? x509Certificate2s
        )
    : IEquatable<CertificateRequestCollection>
{
    public string Id { get; } = id;
    public List<CertificateRequest> CertificateRequests { get; } = certificateRequests;
    public X509Certificate2Collection? X509Certificate2s { get; } = x509Certificate2s;

    public override bool Equals(object? obj)
        => obj is CertificateRequestCollection other && Equals(other);

    public bool Equals(CertificateRequestCollection? other)
    {
        if (other is null) { return false; }
        if (ReferenceEquals(this, other)) { return true; }
        if (Id != other.Id) { return false; }
        if (CertificateRequests.Count != other.CertificateRequests.Count) { return false; }
        for (var i = 0; i < CertificateRequests.Count; i++)
        {
            if (!CertificateRequests[i].Equals(other.CertificateRequests[i])) { return false; }
        }
        if (ReferenceEquals(X509Certificate2s, other.X509Certificate2s)) { return true; }
        if ((X509Certificate2s is { }) != (other.X509Certificate2s is { })) { return false; }
        if (X509Certificate2s is { } collection && other.X509Certificate2s is { } otherCollection)
        {
            if (collection.Count != otherCollection.Count) { return false; }
            for (var i = 0; i < collection.Count; i++)
            {
                if (!collection[i].Equals(otherCollection[i])) { return false; }
            }
        }
        return true;
    }

    public override int GetHashCode()
    {
        var result = new HashCode();
        result.Add(Id);
        foreach (var request in CertificateRequests)
        {
            result.Add(request);
        }
        if (X509Certificate2s is { } collection)
        {
            foreach (var certificate in collection)
            {
                result.Add(certificate);
            }
        }
        return result.ToHashCode();
    }
}
