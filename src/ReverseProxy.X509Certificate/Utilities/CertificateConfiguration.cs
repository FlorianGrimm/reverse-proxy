using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Yarp.ReverseProxy.Utilities;


public class CertificateConfiguration
{
    public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;
    public StoreName StoreName { get; set; } = StoreName.My;
    public string Subject { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string KeyPath { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;

}

public class ListCertificateConfiguration
{
    public List<CertificateConfiguration> Items { get; set; } = new();
}
