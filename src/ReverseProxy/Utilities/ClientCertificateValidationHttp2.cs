using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

using Microsoft.Extensions.Options;

namespace Yarp.ReverseProxy.Utilities;

public sealed class ClientCertificateValidationHttp2Options
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

public sealed class ClientCertificateValidationHttp2
    : IDisposable
{
    private SslPolicyErrors _ignoreSslPolicyErrors;
    private Func<X509Certificate2, X509Chain?, SslPolicyErrors, bool, bool>? _customValidation;
    private readonly ILogger _logger;
    private IDisposable? _ReleaseOnChange;
    private ClientCertificateValidationHttp2Options _options;

    public ClientCertificateValidationHttp2(
        ClientCertificateValidationHttp2Options options,
        ILogger logger
        )
    {
        _options = options;
        ClientCertificateValidationCallback = ClientCertificateValidation;
        RemoteCertificateValidationCallback = RemoteCertificateValidation;
        _logger = logger;
        updateOptions(options, null);
    }

    [Microsoft.Extensions.DependencyInjection.ActivatorUtilitiesConstructor()]
    public ClientCertificateValidationHttp2
        (
        IOptionsMonitor<ClientCertificateValidationHttp2Options> options,
        ILogger<ClientCertificateValidationHttp2> logger
        ) : this(options.CurrentValue, logger)
    {
        _ReleaseOnChange = options.OnChange(updateOptions);
    }

    private void updateOptions(ClientCertificateValidationHttp2Options options, string? key)
    {
        if (!string.IsNullOrEmpty(key))
        {
            return;
        }

        _ignoreSslPolicyErrors = options.IgnoreSslPolicyErrors;
        _customValidation = options.CustomValidation;
    }

    public ClientCertificateValidationHttp2Options Options
    {
        get => _options;
        set
        {
            _options = value;
            updateOptions(value, null);
        }
    }

    public RemoteCertificateValidationCallback RemoteCertificateValidationCallback { get; }
        // = RemoteCertificateValidation

    private bool RemoteCertificateValidation(object sender, X509Certificate? certificate1, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
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
            Log.ClientCertificateValidationSuccess(_logger, certificate2.Subject);
        }
        else
        {
            Log.ClientCertificateValidationFailed(_logger, certificate2.Subject, sslPolicyErrors);
        }
        return result;
    }


    public Func<X509Certificate2 /*certificate*/, X509Chain? /*chain*/, SslPolicyErrors /*sslPolicyErrors*/, bool> ClientCertificateValidationCallback { get; }
        // = ClientCertificateValidation

    private bool ClientCertificateValidation(X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
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
            "Client Certificate validation failed '{clientCertificateSubject}' '{sslPolicyErrors}.");

        public static void ClientCertificateValidationFailed(ILogger logger, string clientCertificateSubject, SslPolicyErrors sslPolicyErrors)
        {
            _ClientCertificateValidationFailed(logger, clientCertificateSubject, sslPolicyErrors, null);
        }

        private static readonly Action<ILogger, string, Exception?> _ClientCertificateValidationSuccess = LoggerMessage.Define<string>(
            LogLevel.Debug,
            EventIds.ClientCertificateValidationSuccess,
            "Client Certificate validation success '{clientCertificateSubject}'.");

        internal static void ClientCertificateValidationSuccess(ILogger logger, string clientCertificateSubject)
        {
            _ClientCertificateValidationSuccess(logger, clientCertificateSubject, null);
        }
    }
}
