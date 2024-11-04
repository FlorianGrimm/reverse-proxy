using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;

public sealed class ClientCertificateValidationOptions
{
    /// <summary>
    /// Ignore the SSL policy errors.
    /// </summary>
    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; } = SslPolicyErrors.None;

    /// <summary>
    /// Specifies the callback method to validate the certificate;
    /// </summary>
    public Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? CustomValidation { get; set; }
}

public sealed class ClientCertificateValidationUtility
    : IDisposable
{
    private SslPolicyErrors _ignoreSslPolicyErrors;
    private Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? _customValidation;
    private readonly ILogger _logger;
    private IDisposable? _ReleaseOnChange;

    public ClientCertificateValidationUtility
        (
        ClientCertificateValidationOptions options,
        ILogger logger
        )
    {
        ClientCertificateValidationCallback = ClientCertificateValidation;
        _logger = logger;
        updateOptions(options, null);
    }

    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor()]
    public ClientCertificateValidationUtility
        (
        IOptionsMonitor<ClientCertificateValidationOptions> options,
        ILogger<ClientCertificateValidationUtility> logger
        ) : this(options.CurrentValue, logger)
    {
        _ReleaseOnChange = options.OnChange(updateOptions);
    }

    private void updateOptions(ClientCertificateValidationOptions options, string? key)
    {
        if (!string.IsNullOrEmpty(key))
        {
            return;
        }

        _ignoreSslPolicyErrors = options.IgnoreSslPolicyErrors;
        _customValidation = options.CustomValidation;
    }

    public Func<X509Certificate2 /*certificate*/, X509Chain? /*chain*/, SslPolicyErrors /*sslPolicyErrors*/, bool> ClientCertificateValidationCallback { get; }

    public bool ClientCertificateValidation(X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate is null)
        {
            return false;
        }

        var result = (sslPolicyErrors == SslPolicyErrors.None);

        if (!result)
        {
            result = (sslPolicyErrors & ~_ignoreSslPolicyErrors) == SslPolicyErrors.None;
        }

        if (_customValidation is { } customValidation)
        {
            result = customValidation(certificate, chain, sslPolicyErrors, result);
        }

        if (result)
        {
            Log.ClientCertificateValidationSuccess(_logger, certificate.Subject);
        }
        else
        {
            Log.ClientCertificateValidationFailed(_logger, certificate.Subject, sslPolicyErrors);
        }
        return result;
    }

    public void Dispose()
    {
        using (var releaseOnChange = _ReleaseOnChange)
        {
            _ReleaseOnChange = null;
        }
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, SslPolicyErrors, Exception?> _ClientCertificateValidationFailed = LoggerMessage.Define<string, SslPolicyErrors>(
            LogLevel.Information,
            EventIds.ClientCertificateValidationFailed,
            "Client Certificate validation failed '{clientCertificateSubjet}' '{sslPolicyErrors}.");

        public static void ClientCertificateValidationFailed(ILogger logger, string clientCertificateSubjet, SslPolicyErrors sslPolicyErrors)
        {
            _ClientCertificateValidationFailed(logger, clientCertificateSubjet, sslPolicyErrors, null);
        }

        private static readonly Action<ILogger, string, Exception?> _ClientCertificateValidationSuccess = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.ClientCertificateValidationSuccess,
            "Client Certificate validation success '{clientCertificateSubjet}'.");

        internal static void ClientCertificateValidationSuccess(ILogger logger, string clientCertificateSubjet)
        {
            _ClientCertificateValidationSuccess(logger, clientCertificateSubjet, null);
        }
    }
}
