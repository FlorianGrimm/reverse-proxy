using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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
}

public class CertificateStoreLoader: ICertificateStoreLoader
{
}
