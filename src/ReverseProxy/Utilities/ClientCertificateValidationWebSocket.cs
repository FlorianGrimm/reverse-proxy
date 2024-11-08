using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;

public sealed class ClientCertificateValidationWebSocketOptions
{
    public SslPolicyErrors IgnoreSslPolicyErrors { get; set; } = SslPolicyErrors.None;
    public Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? CustomValidation { get; set; }
}

/// <summary>
/// Provides a callback for remote certificate validation.
/// </summary>
public sealed class ClientCertificateValidationWebSocket
    : IDisposable
{
    private ClientCertificateValidationWebSocketOptions _options;
    private SslPolicyErrors _ignoreSslPolicyErrors;
    private Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? _customValidation;
    private readonly ILogger _logger;
    private IDisposable? _releaseOnChange;

    public ClientCertificateValidationWebSocket(
        ClientCertificateValidationWebSocketOptions options,
        ILogger logger
        )
    {
        _options = options;
        _logger = logger;
        RemoteCertificateValidationCallback = ((object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => ClientCertificateValidation(certificate, chain, sslPolicyErrors));
        ClientCertificateValidationCallback = ClientCertificateValidation;

        updateOptions(options, null);
    }

    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor()]
    public ClientCertificateValidationWebSocket
        (
        IOptionsMonitor<ClientCertificateValidationWebSocketOptions> options,
        ILogger<ClientCertificateValidationWebSocket> logger
        ) : this(options.CurrentValue, logger)
    {
        _releaseOnChange = options.OnChange(updateOptions);
    }


    private void updateOptions(ClientCertificateValidationWebSocketOptions options, string? key)
    {
        if (!string.IsNullOrEmpty(key))
        {
            return;
        }

        _ignoreSslPolicyErrors = options.IgnoreSslPolicyErrors;
        _customValidation = options.CustomValidation;
    }

    public ClientCertificateValidationWebSocketOptions Options
    {
        get => _options;
        set
        {
            _options = value;
            updateOptions(value, null);
        }
    }

    public System.Net.Security.RemoteCertificateValidationCallback RemoteCertificateValidationCallback { get; }

    public Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool> ClientCertificateValidationCallback { get;  }
    
    public bool ClientCertificateValidation(X509Certificate? certificate1, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate1 is null)
        {
            return false;
        }
        var certificate2 = certificate1 is X509Certificate2 c ? c : new X509Certificate2(certificate1);

        var result = (sslPolicyErrors == SslPolicyErrors.None);

        if (!result)
        {
            result = (sslPolicyErrors & ~_ignoreSslPolicyErrors) == SslPolicyErrors.None;
        }

        if (_customValidation is { } customValidation)
        {
            result = customValidation(certificate2, chain, sslPolicyErrors, result);
        }

        if (result)
        {
            Log.RemoteCertificateValidationSuccess(_logger, certificate2.Subject);
        }
        else
        {
            Log.RemoteCertificateValidationFailed(_logger, certificate2.Subject, sslPolicyErrors);
        }
        return result;
    }

    public void Dispose()
    {
        using (var releaseOnChange = _releaseOnChange)
        {
            _releaseOnChange = null;
        }
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, SslPolicyErrors, Exception?> _remoteCertificateValidationFailed = LoggerMessage.Define<string, SslPolicyErrors>(
            LogLevel.Information,
            EventIds.RemoteCertificateValidationFailed,
            "Remote Certificate validation failed '{clientCertificateSubject}' '{sslPolicyErrors}.");

        public static void RemoteCertificateValidationFailed(ILogger logger, string clientCertificateSubject, SslPolicyErrors sslPolicyErrors)
        {
            _remoteCertificateValidationFailed(logger, clientCertificateSubject, sslPolicyErrors, null);
        }

        private static readonly Action<ILogger, string, Exception?> _remoteCertificateValidationSuccess = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.RemoteCertificateValidationSuccess,
            "Remote Certificate validation success '{clientCertificateSubject}'.");

        internal static void RemoteCertificateValidationSuccess(ILogger logger, string clientCertificateSubject)
        {
            _remoteCertificateValidationSuccess(logger, clientCertificateSubject, null);
        }
    }
}
