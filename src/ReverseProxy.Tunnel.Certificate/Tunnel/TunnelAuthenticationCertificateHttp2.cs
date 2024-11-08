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
using System.Collections.Concurrent;

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
internal sealed class TunnelAuthenticationCertificateHttp2
    : ITunnelAuthenticationService
{
    private static readonly Oid ClientCertificateOid = new Oid("1.3.6.1.5.5.7.3.2");

    public const string AuthenticationScheme = "Certificate";
    public const string AuthenticationName = "ClientCertificate";
    public const string CookieName = "YarpTunnelAuth";
    private readonly ClientCertificateValidationHttp2 _clientCertificateValidation;
    private readonly TunnelAuthenticationCertificateOptions _options;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger _logger;

    private readonly CertificateRequestCollectionDictionary _clientCertificateCollectionByTunnelId;

    public TunnelAuthenticationCertificateHttp2(
        IOptions<TunnelAuthenticationCertificateOptions> options,
        ICertificateManager certificateManager,
        ILogger<TunnelAuthenticationCertificateHttp2> logger
        )
    {
        _options = options.Value;
        _certificateManager = certificateManager;
        _logger = logger;
        _clientCertificateValidation = new ClientCertificateValidationHttp2(
#warning TODO
            new ClientCertificateValidationHttp2Options() {
                CustomValidation = _options.CustomValidation,
                IgnoreSslPolicyErrors = _options.IgnoreSslPolicyErrors
            },
            logger);

        _clientCertificateCollectionByTunnelId = new CertificateRequestCollectionDictionary(
            certificateManager,
            nameof(TunnelAuthenticationCertificateHttp2),
            _options.CertificateRequirement,
            adjustCertificateRequirement);
    }

    private static CertificateRequirement adjustCertificateRequirement(CertificateRequirement requirement)
        => requirement with { ClientCertificate = true, NeedPrivateKey = true };

    public string GetAuthenticationMode() => AuthenticationName;

    public string GetTransport() => "TunnelHTTP2";

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

    /// <summary>
    /// Configure the Kestrel server options for the tunnel.
    /// </summary>
    /// <param name="httpsOptions">the options to modify.</param>
    private void ConfigureHttpsConnectionAdapterOptions(HttpsConnectionAdapterOptions httpsOptions)
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        // httpsOptions.ServerCertificateSelector = _clientCertificateValidationUtility.ServerCertificateSelectorCallback;
        httpsOptions.ClientCertificateValidation = _clientCertificateValidation.ClientCertificateValidationCallback;

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

        var config = cluster.Model.Config;
        if (!IsClientCertificate(config.Authentication.Mode))
        {
            return false;
        }
        var parameter = config.Authentication.ToParameter(cluster.ClusterId);
        if (parameter.IsEmpty())
        {
            if (!ValidateCertificateAsync(clientCertificate))
            {
                Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, AuthenticationName, clientCertificate.Subject);
                return false;
            }

            return true;
        }
        else
        {
            var certificateRequestCollection = _clientCertificateCollectionByTunnelId.GetOrAddConfiguration(parameter);

            using (var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(certificateRequestCollection))
            {
                if (!(shareCurrentCertificateCollection?.Value is { Count: > 0 } currentCertificateCollection))
                {
                    _logger.LogWarning("No certificates for cluster {ClusterId}.", cluster.ClusterId);
                    return false;
                }

                var clientCertificateThumbprint = clientCertificate.Thumbprint;
                foreach (var clusterCertificate in currentCertificateCollection)
                {
                    if (string.Equals(clusterCertificate.Thumbprint, clientCertificateThumbprint, System.StringComparison.Ordinal)
                        && clusterCertificate.Equals(clientCertificate))
                    {
                        Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, AuthenticationName, clusterCertificate.Subject);
                        return true;
                    }
                }

                {
                    Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, clientCertificate.Subject);
                    return false;
                }
            }
        }
    }

#warning HERE ValidateCertificateAsync
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

    public static bool IsClientCertificate(string? mode)
        => string.Equals(mode, "ClientCertificate", System.StringComparison.OrdinalIgnoreCase);

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
            "Cluster {clusterId} Authentication {AuthenticationName} failed for {subject}.");

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
