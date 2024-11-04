namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// The default implementation of <see cref="ICertificatePasswordProvider"/>.
/// Can be used if you don't encrypt the password - or not use a password.
/// </summary>
public class CertificatePasswordProvider : ICertificatePasswordProvider
{
    public string DecryptPassword(string value)
    {
        return value;
    }
}
