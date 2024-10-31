using System;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;

public record struct CertificateStoreLocationName(
    StoreLocation StoreLocation,
    StoreName StoreName
    )
{
    public static CertificateStoreLocationName? Convert(
        string? storeLocation,
        string? storeName
        )
    {
        if (string.IsNullOrEmpty(storeLocation) || string.IsNullOrEmpty(storeName))
        {
            return null;
        }
        return new CertificateStoreLocationName(storeLocation, storeName);
    }

    public CertificateStoreLocationName(
        string storeLocation,
        string storeName
        ) : this(
            (string.Equals(storeLocation, "LocalMachine", StringComparison.OrdinalIgnoreCase)
                ? StoreLocation.LocalMachine
                : StoreLocation.CurrentUser),
            (System.Enum.TryParse<StoreName>(storeName, true, out var storeNameEnum)
                ? storeNameEnum
                : StoreName.My)
            )
    {
    }
}
