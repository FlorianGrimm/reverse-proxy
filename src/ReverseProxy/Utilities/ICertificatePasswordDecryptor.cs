namespace Yarp.ReverseProxy.Utilities;

public interface ICertificatePasswordDecryptor
{
    string? DecryptPassword(string? value);
}

public sealed class NoOpCertificatePasswordDecryptor : ICertificatePasswordDecryptor
{
    public string? DecryptPassword(string? value) => value;
}
