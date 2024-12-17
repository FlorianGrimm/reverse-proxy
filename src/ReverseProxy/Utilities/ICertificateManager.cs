// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Allows to load certificates.
/// </summary>
public interface ICertificateManager
{
    /// <summary>
    /// Get the certificate collection defined by.
    /// </summary>
    /// <param name="certificateId">identifies the certificates to return (and may be load).</param>
    /// <returns>the (valid) certificates</returns>
    /// <remarks>
    /// Gives the opportunity to reuse your favorite library.
    /// </remarks>
    ISharedValue<X509Certificate2Collection?> GetCertificateCollection(string certificateId);
}

public sealed class NoOpCertificateManager : ICertificateManager
{
    public ISharedValue<X509Certificate2Collection?> GetCertificateCollection(string certificateId)
        => new EmptySharedValue<X509Certificate2Collection>();
}

public sealed class EmptySharedValue<T>
    : ISharedValue<T?>
    where T : class
{
    public T? Value => null;

    public T? GiveAway() => null;

    public void Dispose() { }

}
