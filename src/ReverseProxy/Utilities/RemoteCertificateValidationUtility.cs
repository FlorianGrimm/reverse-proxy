using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;

public sealed class RemoteCertificateValidationOptions
{
    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; } = SslPolicyErrors.None;
    public Func<X509Certificate, X509Chain?, SslPolicyErrors, bool, bool>? CustomValidation { get; set; }
}

public sealed class RemoteCertificateValidationUtility
    : IDisposable
{
    private SslPolicyErrors _ignoreSslPolicyErrors;
    private Func<X509Certificate, X509Chain?, SslPolicyErrors, bool, bool>? _customValidation;
    private readonly ILogger _logger;
    private IDisposable? _ReleaseOnChange;

    public RemoteCertificateValidationUtility
        (
        RemoteCertificateValidationOptions options,
        ILogger logger
        )
    {
        _logger = logger;
        RemoteCertificateValidationCallback = ((object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => ClientCertificateValidation(certificate, chain, sslPolicyErrors));

        updateOptions(options, null);
    }

    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor()]
    public RemoteCertificateValidationUtility
        (
        IOptionsMonitor<RemoteCertificateValidationOptions> options,
        ILogger<RemoteCertificateValidationUtility> logger
        ) : this(options.CurrentValue, logger)
    {
        _ReleaseOnChange = options.OnChange(updateOptions);
    }

    private void updateOptions(RemoteCertificateValidationOptions options, string? key)
    {
        if (!string.IsNullOrEmpty(key))
        {
            return;
        }

        _ignoreSslPolicyErrors = options.IgnoreSslPolicyErrors;
        _customValidation = options.CustomValidation;
    }

    public System.Net.Security.RemoteCertificateValidationCallback RemoteCertificateValidationCallback { get; }

    public bool ClientCertificateValidation(X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
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
            Log.RemoteCertificateValidationSuccess(_logger, certificate.Subject);
        }
        else
        {
            Log.RemoteCertificateValidationFailed(_logger, certificate.Subject, sslPolicyErrors);
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
        private static readonly Action<ILogger, string, SslPolicyErrors, Exception?> _remoteCertificateValidationFailed = LoggerMessage.Define<string, SslPolicyErrors>(
            LogLevel.Information,
            EventIds.RemoteCertificateValidationFailed,
            "Remote Certificate validation failed '{clientCertificateSubjet}' '{sslPolicyErrors}.");

        public static void RemoteCertificateValidationFailed(ILogger logger, string clientCertificateSubjet, SslPolicyErrors sslPolicyErrors)
        {
            _remoteCertificateValidationFailed(logger, clientCertificateSubjet, sslPolicyErrors, null);
        }

        private static readonly Action<ILogger, string, Exception?> _remoteCertificateValidationSuccess = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RemoteCertificateValidationSuccess,
            "Remote Certificate validation succcess '{clientCertificateSubjet}'.");

        internal static void RemoteCertificateValidationSuccess(ILogger logger, string clientCertificateSubjet)
        {
            _remoteCertificateValidationSuccess(logger, clientCertificateSubjet, null);
        }
    }
}
