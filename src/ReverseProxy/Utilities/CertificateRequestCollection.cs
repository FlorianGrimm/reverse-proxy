using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Represents a collection of certificate requests and associated X509 certificates.
/// </summary>
#if DEBUG
[DebuggerDisplay($"{{{nameof(GetDebuggerDisplay)}(),nq}}")]
#endif
public sealed class CertificateRequestCollection(
        string id,
        List<CertificateRequest> certificateRequests,
        X509Certificate2Collection? x509Certificate2s
        )
    : IEquatable<CertificateRequestCollection> {
#if DEBUG
    private static int _nextSeqId = 0;
    private readonly int _seqId = System.Threading.Interlocked.Increment(ref _nextSeqId);
#endif

    /// <summary>
    /// Gets the identifier for this definition.
    /// </summary>
    public string Id { get; } = id;

    /// <summary>
    /// Gets the list of certificate requests.
    /// </summary>
    public List<CertificateRequest> CertificateRequests { get; } = certificateRequests;

    /// <summary>
    /// Gets the collection of X509 certificates.
    /// </summary>
    public X509Certificate2Collection? X509Certificate2s { get; } = x509Certificate2s;

    /// <summary>
    /// Determines whether the specified object is equal to the current object.
    /// </summary>
    /// <param name="obj">The object to compare with the current object.</param>
    /// <returns>true if the specified object is equal to the current object; otherwise, false.</returns>
    public override bool Equals(object? obj)
        => obj is CertificateRequestCollection other && Equals(other);

    /// <summary>
    /// Determines whether the specified <see cref="CertificateRequestCollection"/> is equal to the current <see cref="CertificateRequestCollection"/>.
    /// </summary>
    /// <param name="other">The <see cref="CertificateRequestCollection"/> to compare with the current <see cref="CertificateRequestCollection"/>.</param>
    /// <returns>true if the specified <see cref="CertificateRequestCollection"/> is equal to the current <see cref="CertificateRequestCollection"/>; otherwise, false.</returns>
    public bool Equals(CertificateRequestCollection? other) {
        if (other is null) { return false; }
        if (ReferenceEquals(this, other)) { return true; }
        if (Id != other.Id) { return false; }
        if (CertificateRequests.Count != other.CertificateRequests.Count) { return false; }
        for (var i = 0; i < CertificateRequests.Count; i++) {
            if (!CertificateRequests[i].Equals(other.CertificateRequests[i])) { return false; }
        }
        if (ReferenceEquals(X509Certificate2s, other.X509Certificate2s)) { return true; }
        if ((X509Certificate2s is { }) != (other.X509Certificate2s is { })) { return false; }
        if (X509Certificate2s is { } collection && other.X509Certificate2s is { } otherCollection) {
            if (collection.Count != otherCollection.Count) { return false; }
            for (var i = 0; i < collection.Count; i++) {
                if (!collection[i].Equals(otherCollection[i])) { return false; }
            }
        }
        return true;
    }

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current object.</returns>
    public override int GetHashCode() {
        var result = new HashCode();
        result.Add(Id);
        foreach (var request in CertificateRequests) {
            result.Add(request);
        }
        if (X509Certificate2s is { } collection) {
            foreach (var certificate in collection) {
                result.Add(certificate);
            }
        }
        return result.ToHashCode();
    }
#if DEBUG
    private string GetDebuggerDisplay()
    {
        return _seqId.ToString();
    }
#endif
}
