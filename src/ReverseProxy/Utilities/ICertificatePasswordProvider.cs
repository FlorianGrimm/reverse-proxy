namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Provides a password for a certificate.
/// </summary>
public interface ICertificatePasswordProvider
{
    string DecryptPassword(string value);
}

public class CertificatePasswordProvider : ICertificatePasswordProvider
{
    public string DecryptPassword(string value)
    {
        return value;
    }
}
