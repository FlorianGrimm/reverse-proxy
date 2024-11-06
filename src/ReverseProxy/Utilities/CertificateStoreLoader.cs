using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Yarp.ReverseProxy.Utilities;

public record struct CertificateStoreRequest(
    CertificateStoreLocationName? StoreLocationName,
    string? Subject

    //CertificateRequirement Requirement
    )
{
    public static CertificateStoreRequest? Convert(
        CertificateStoreLocationName? storeLocationName,
        string? subject
        )
    {
        if (storeLocationName == null || string.IsNullOrEmpty(subject))
        {
            return null;
        }
        return new CertificateStoreRequest(storeLocationName, subject);
    }

    [MemberNotNullWhen(true, nameof(Subject))]
    [MemberNotNullWhen(true, nameof(StoreLocationName))]
    public bool IsValid() => (StoreLocationName.HasValue)
        && !string.IsNullOrEmpty(Subject);
}

public interface ICertificateStoreLoader
{
    List<X509Certificate2> Load<TArg>(
        CertificateStoreLocationName storeLocationName,
        TArg arg,
        Func<X509Certificate2, TArg, bool> handle);
}

public class CertificateStoreLoader : ICertificateStoreLoader
{
    public List<X509Certificate2> Load<TArg>(
        CertificateStoreLocationName storeLocationName,
        TArg arg,
        Func<X509Certificate2, TArg, bool> handle)
    {
        var result = new List<X509Certificate2>();
        using (var store = new X509Store(storeLocationName.StoreName, storeLocationName.StoreLocation))
        {
            X509Certificate2Collection? storeCertificates = null;
            try
            {
                store.Open(OpenFlags.ReadOnly);
                storeCertificates = store.Certificates;
                for (var index = 0; index < storeCertificates.Count; index++)
                {
                    var certificate = storeCertificates[index];
                    // check which CertificateRequest is interested in this certificate
                    var isInterested = handle(certificate, arg);
                    
                    if (isInterested)
                    {
                        storeCertificates.RemoveAt(index);
                    }
                    else
                    {
                        // if no CertificateRequest is interested in this certificate dispose it finally
                        result.Add(certificate);
                    }
                }

            }
            finally
            {
                storeCertificates.DisposeCertificates(null);
            }
        }
        return result;
    }
}
