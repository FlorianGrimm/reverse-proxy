namespace Yarp.ReverseProxy.Utilities;

/// <summary>
/// Provides a password for a certificate.
/// </summary>
public interface ICertificatePasswordProvider
{
    // TODO: can we provide more context here?
    /// <summary>
    /// Decrypts the password.
    /// </summary>
    /// <param name="value">The encrypted password</param>
    /// <returns>The decrypted password.</returns>
    string DecryptPassword(string value);
}

// TODO: is simple to use the windows user en/de-cryption thing?
