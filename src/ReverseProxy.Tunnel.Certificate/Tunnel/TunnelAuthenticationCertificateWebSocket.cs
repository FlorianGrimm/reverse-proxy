// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

using Microsoft.AspNetCore.Authentication.Certificate;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using System.Security.Principal;

namespace Yarp.ReverseProxy.Tunnel;

/// <summary>
/// Enables or disables the client certificate tunnel authentication.
/// A client certificate is required for the tunnel.
/// You have to configure the authentication, e.g.
/// <code>
///    builder.Services.AddAuthentication()
///        .AddCertificate(options =>
///        {
///            options.AllowedCertificateTypes = CertificateTypes.Chained;
///            options.RevocationMode = ....;
///        });
/// </code>
/// </summary>
///
internal sealed class TunnelAuthenticationCertificateWebSocket
    : ITunnelAuthenticationService
    , IClusterChangeListener
    , IDisposable
{
    private static readonly Oid ClientCertificateOid = new Oid("1.3.6.1.5.5.7.3.2");

    public const string AuthenticationScheme = "Certificate";
    public const string AuthenticationName = "ClientCertificate";
    public const string CookieName = "YarpTunnelAuth";
    private readonly YarpClientCertificateValidationUtility _clientCertificateValidationUtility;
    private readonly TunnelAuthenticationCertificateOptions _options;
    private readonly ILazyRequiredServiceResolver<IProxyStateLookup> _proxyConfigManagerLazy;
    private readonly ITunnelAuthenticationCookieService _cookieService;
    private readonly IYarpCertificateLoader _certificateConfigLoader;
    private readonly YarpCertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger _logger;
    private IDisposable? _unregisterCertificatePathWatcher;
    private ImmutableDictionary<string, X509Certificate2>? _validCertificatesByThumbprint;
    private ImmutableDictionary<string, X509Certificate2>? _validCertificatesByCluster;

    public TunnelAuthenticationCertificateWebSocket(
        IOptions<TunnelAuthenticationCertificateOptions> options,
        ILazyRequiredServiceResolver<IProxyStateLookup> proxyConfigManagerLazy,
        YarpClientCertificateValidationUtility clientCertificateValidationUtility,
        ITunnelAuthenticationCookieService cookieService,
        IYarpCertificateLoader certificateConfigLoader,
        YarpCertificatePathWatcher certificatePathWatcher,
        ILogger<TunnelAuthenticationCertificateWebSocket> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _clientCertificateValidationUtility = clientCertificateValidationUtility;
        _cookieService = cookieService;
        _certificateConfigLoader = certificateConfigLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;



        _unregisterCertificatePathWatcher = ChangeToken.OnChange(
            _certificatePathWatcher.GetChangeToken,
            () => ClearCertificateCache()
            );
    }

    public string GetAuthenticationMode() => AuthenticationName;

    public string GetTransport() => "TunnelWebSocket";

    public ITunnelAuthenticationService GetAuthenticationService(string protocol) => this;

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        kestrelServerOptions.ConfigureHttpsDefaults((HttpsConnectionAdapterOptions httpsOptions) =>
        {
            ConfigureHttpsConnectionAdapterOptions(httpsOptions);
        });
        kestrelServerOptions.ConfigureEndpointDefaults((ListenOptions listenOptions) =>
        {
            listenOptions.UseHttps(ConfigureHttpsConnectionAdapterOptions);
        });
    }

    internal void ConfigureHttpsConnectionAdapterOptions(HttpsConnectionAdapterOptions httpsOptions)
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        httpsOptions.ClientCertificateValidation = _clientCertificateValidationUtility.ClientCertificateValidationCallback;
        if (_options.CheckCertificateRevocation.HasValue)
        {
            httpsOptions.CheckCertificateRevocation = _options.CheckCertificateRevocation.Value;
        }
        if (_options.SslProtocols.HasValue)
        {
            httpsOptions.SslProtocols = _options.SslProtocols.Value;
        }
        if (_options.ConfigureHttpsConnectionAdapterOptions is { } configure)
        {
            configure(httpsOptions);
        }
    }

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
    }

    public void OnClusterAdded(ClusterState cluster)
    {
        ClearCertificateCache();
    }

    public void OnClusterChanged(ClusterState cluster)
    {
        ClearCertificateCache();
    }

    public void OnClusterRemoved(ClusterState cluster)
    {
        ClearCertificateCache();
    }

    private (ImmutableDictionary<string, X509Certificate2> validCertificatesByThumbprint, ImmutableDictionary<string, X509Certificate2> validCertificatesByCluster) LoadCertificates()
    {
        var resultCertificatesByThumbprint = new Dictionary<string, X509Certificate2>();
        var resultCertificatesByCluster = new Dictionary<string, X509Certificate2>();
        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
        foreach (var cluster in proxyConfigManager.GetTransportTunnelClusters())
        {
            var config = cluster.Model.Config;
            if (!YarpClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
            {
                continue;
            }
            if (config.Authentication.ClientCertificate is { } clientCertificate)
            {
                // TODO: does this work??
                // var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateNoPrivateKey(clientCertificate, cluster.ClusterId);
                var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateWithPrivateKey(clientCertificate, cluster.ClusterId);
                YarpClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
                if (certificate is not null)
                {
                    var thumbprint = certificate.Thumbprint;

                    if (resultCertificatesByThumbprint.TryAdd(thumbprint, certificate))
                    {
                        // OK
                        resultCertificatesByCluster[config.ClusterId] = certificate;
                    }
                    else
                    {
                        resultCertificatesByCluster[config.ClusterId] = resultCertificatesByThumbprint[thumbprint];
                        // already added forget this
                        certificate.Dispose();
                    }
                }
            }
        }

        var validCertificatesByThumbprint = resultCertificatesByThumbprint.ToImmutableDictionary();
        var validCertificatesByCluster = resultCertificatesByCluster.ToImmutableDictionary();

        _validCertificatesByThumbprint = validCertificatesByThumbprint;
        _validCertificatesByCluster = validCertificatesByCluster;
        System.Threading.Interlocked.MemoryBarrier();
        return (validCertificatesByThumbprint, validCertificatesByCluster);
    }

    private void ClearCertificateCache()
    {
        lock (this)
        {
            _validCertificatesByThumbprint = null;
            _validCertificatesByCluster = null;
        }
    }

    public async ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        var isAuthenticatedSourceRequest = await CheckTunnelRequestIsAuthenticatedSourceRequest(context, cluster);
        if (isAuthenticatedSourceRequest)
        {
            return null;
        }
        else
        {
            return Results.Forbid();
        }
    }

    public async ValueTask<bool> CheckTunnelRequestIsAuthenticatedSourceRequest(HttpContext context, ClusterState cluster)
    {
        if (!context.Request.IsHttps)
        {
            Log.NotHttps(_logger);
            return false;
        }

        var clientCertificate = await context.Connection.GetClientCertificateAsync();
        if (clientCertificate is null)
        {
            Log.NoCertificate(_logger);
            return false;
        }

        if (!ValidateCertificateAsync(clientCertificate))
        {
            return false;
        }


        // ensure the certificates are loaded
        var validCertificatesByCluster = _validCertificatesByCluster;
        var validCertificatesByThumbprint = _validCertificatesByThumbprint;
        if (validCertificatesByThumbprint is null)
        {
            lock (this)
            {
                validCertificatesByCluster = _validCertificatesByCluster;
                validCertificatesByThumbprint = _validCertificatesByThumbprint;
                if (validCertificatesByThumbprint is null)
                {
                    (validCertificatesByThumbprint, validCertificatesByCluster) = LoadCertificates();
                }
            }
        }

        if (validCertificatesByCluster is null)
        {
            _logger.LogWarning("validCertificatesByCluster is null.");
            return false;
        }

        if (!validCertificatesByCluster.TryGetValue(cluster.ClusterId, out var certificate))
        {
            _logger.LogWarning("validCertificatesByCluster {ClusterId} not found.", cluster.ClusterId);
            return false;
        }

        var result = string.Equals(certificate.Thumbprint, clientCertificate.Thumbprint, System.StringComparison.Ordinal);
        if (result)
        {
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, AuthenticationName, certificate.Subject);
            return true;
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, certificate.Subject);
            return false;
        }
    }

    private bool ValidateCertificateAsync(X509Certificate2 clientCertificate)
    {
        var isCertificateSelfSigned = clientCertificate.IsSelfSigned();

        // If we have a self signed cert, and they're not allowed, exit early and not bother with
        // any other validations.
        if (isCertificateSelfSigned &&
            !_options.AllowedCertificateTypes.HasFlag(CertificateTypes.SelfSigned))
        {
            Log.CertificateRejected(_logger, "Self signed", clientCertificate.Subject);
            return false;
        }

        // If we have a chained cert, and they're not allowed, exit early and not bother with
        // any other validations.
        if (!isCertificateSelfSigned &&
            !_options.AllowedCertificateTypes.HasFlag(CertificateTypes.Chained))
        {
            Log.CertificateRejected(_logger, "Chained", clientCertificate.Subject);
            return false;
        }

        var chainPolicy = BuildChainPolicy(clientCertificate, isCertificateSelfSigned);
        using var chain = new X509Chain
        {
            ChainPolicy = chainPolicy
        };

        var certificateIsValid = chain.Build(clientCertificate);
        if (!certificateIsValid)
        {
            if (Log.IsCertificateFailedValidationEnabled(_logger))
            {
                var chainErrors = new List<string>(chain.ChainStatus.Length);
                foreach (var validationFailure in chain.ChainStatus)
                {
                    chainErrors.Add($"{validationFailure.Status} {validationFailure.StatusInformation}");
                }
                Log.CertificateFailedValidation(_logger, clientCertificate.Subject, chainErrors);
            }
            return false;
        }

        return true;
    }

    private X509ChainPolicy BuildChainPolicy(X509Certificate2 certificate, bool isCertificateSelfSigned)
    {
        // Now build the chain validation options.
        var revocationFlag = _options.RevocationFlag;
        var revocationMode = _options.RevocationMode;

        if (isCertificateSelfSigned)
        {
            // Turn off chain validation, because we have a self signed certificate.
            revocationFlag = X509RevocationFlag.EntireChain;
            revocationMode = X509RevocationMode.NoCheck;
        }

        var chainPolicy = new X509ChainPolicy
        {
            RevocationFlag = revocationFlag,
            RevocationMode = revocationMode,
        };

        if (_options.ValidateCertificateUse)
        {
            chainPolicy.ApplicationPolicy.Add(ClientCertificateOid);
        }

        if (isCertificateSelfSigned)
        {
            chainPolicy.VerificationFlags |= X509VerificationFlags.AllowUnknownCertificateAuthority;
            chainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreEndRevocationUnknown;
            chainPolicy.ExtraStore.Add(certificate);
        }
        else
        {
            if (_options.CustomTrustStore is { } customTrustStore)
            {
                chainPolicy.CustomTrustStore.AddRange(customTrustStore);
            }

            chainPolicy.TrustMode = _options.ChainTrustValidationMode;
        }

        chainPolicy.ExtraStore.AddRange(_options.AdditionalChainCertificates);

        if (!_options.ValidateValidityPeriod)
        {
            chainPolicy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;
        }

        return chainPolicy;
    }

    private void Dispose(bool disposing)
    {
        using (var unregister = _unregisterCertificatePathWatcher)
        {
            if (disposing)
            {
                _unregisterCertificatePathWatcher = null;
            }
        }
    }

    ~TunnelAuthenticationCertificateWebSocket()
    {
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, string, string, Exception?> _clusterAuthenticationSuccess = LoggerMessage.Define<string, string, string>(
            LogLevel.Debug,
            EventIds.ClusterAuthenticationSuccess,
            "Cluster {clusterId} Authentication {AuthenticationName} success {subject}.");

        public static void ClusterAuthenticationSuccess(ILogger logger, string clusterId, string authenticationName, string subject)
        {
            _clusterAuthenticationSuccess(logger, clusterId, authenticationName, subject, null);
        }

        private static readonly Action<ILogger, string, string, string, Exception?> _clusterAuthenticationFailed = LoggerMessage.Define<string, string, string>(
            LogLevel.Information,
            EventIds.ClusterAuthenticationFailed,
            "Cluster {clusterId} Authentication {AuthenticationName} failed {subject}.");

        public static void ClusterAuthenticationFailed(ILogger logger, string clusterId, string authenticationName, string subject)
        {
            _clusterAuthenticationFailed(logger, clusterId, authenticationName, subject, null);
        }
        private static readonly Action<ILogger, Exception?> _noCertificate = LoggerMessage.Define(
            LogLevel.Debug,
            EventIds.NoCertificate,
            "No client certificate found.");

        public static void NoCertificate(ILogger logger)
        {
            _noCertificate(logger, null);
        }

        private static readonly Action<ILogger, Exception?> _notHttps = LoggerMessage.Define(
            LogLevel.Debug,
            EventIds.NotHttps,
            "Not https, skipping certificate authentication..");

        public static void NotHttps(ILogger logger)
        {
            _notHttps(logger, null);
        }

        private static readonly Action<ILogger, string, string, Exception?> _certificateRejected = LoggerMessage.Define<string, string>(
            LogLevel.Warning,
            EventIds.CertificateRejected,
            "{CertificateType} certificate rejected, subject was {Subject}.");

        public static void CertificateRejected(ILogger logger, string certificateType, string subject)
        {
            _certificateRejected(logger, certificateType, subject, null);
        }

        private static readonly Action<ILogger, string, IList<string>, Exception?> _certificateFailedValidation = LoggerMessage.Define<string, IList<string>>(
            LogLevel.Information,
            EventIds.CertificateFailedValidation,
            "Certificate validation failed, subject was {Subject}. {ChainErrors}");

        public static void CertificateFailedValidation(ILogger logger, string subject, IList<string> chainErrors)
        {
            _certificateFailedValidation(logger, subject, chainErrors, null);
        }

        public static bool IsCertificateFailedValidationEnabled(ILogger logger) => logger.IsEnabled(LogLevel.Information);

        /*
        private static readonly Action<ILogger, string, string, string, Exception?> _x = LoggerMessage.Define<string, string, string>(
            LogLevel.Information,
            EventIds.ClusterAuthenticationFailed,
            "Cluster {clusterId} Authentication {AuthenticationName} failed {subject}.");

        public static void X(ILogger logger, string clusterId, string authenticationName, string subject)
        {
            _x(logger, clusterId, authenticationName, subject, null);
        }
        */
    }
}
