namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Provides a password for a certificate.
/// </summary>
public interface ICertificatePasswordProvider
{
    /// <summary>
    /// Decrypts the password.
    /// </summary>
    /// <param name="value">The encrypted password</param>
    /// <returns>The decrypted password.</returns>
    string DecryptPassword(string value);
}
