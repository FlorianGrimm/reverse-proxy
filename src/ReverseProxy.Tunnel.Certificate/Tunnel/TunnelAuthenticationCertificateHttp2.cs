// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

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

    private readonly TunnelAuthenticationCertificateOptions _options;
    private readonly ICertificateManager _certificateManager;
    private readonly ILogger _logger;

    public TunnelAuthenticationCertificateHttp2(
        IOptions<TunnelAuthenticationCertificateOptions> options,
        ICertificateManager certificateManager,
        ILogger<TunnelAuthenticationCertificateHttp2> logger
        )
    {
        _options = options.Value;
        _certificateManager = certificateManager;
        _logger = logger;
    }
    public string GetAuthenticationMode() => TunnelCertificateConstants.AuthenticationMode;

    public string GetTransport() => TunnelConstants.TransportNameTunnelHTTP2;

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
        httpsOptions.ClientCertificateValidation = OnClientCertificateValidation;

        if (_options.CheckCertificateRevocation.HasValue)
        {
            httpsOptions.CheckCertificateRevocation = _options.CheckCertificateRevocation.Value;
        }
        if (_options.SslProtocols.HasValue)
        {
            httpsOptions.SslProtocols = _options.SslProtocols.Value;
        }
        if (_options.ConfigureHttpsConnectionAdapterOptions is { } configureHttpsConnectionAdapterOptions)
        {
            configureHttpsConnectionAdapterOptions(httpsOptions);
        }
    }

    private bool OnClientCertificateValidation(
        X509Certificate2 certificate,
        X509Chain? chain,
        SslPolicyErrors errors)
    {
        var result = SslPolicyErrors.None == (errors & ~_options.IgnoreSslPolicyErrors);
        if (_options.CustomValidation is { } customValidation)
        {
            result = customValidation(certificate, chain, errors, result);
        }
        return result;
    }


    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
        conventionBuilder.RequireAuthorization(TunnelCertificateConstants.PolicyName);
        conventionBuilder.WithMetadata(
            new TunnelAuthenticationSchemeMetadata(
                TunnelCertificateConstants.AuthenticationScheme));
    }

    public async ValueTask<IResult?> CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
#warning TODO HACK
#if HACK
        var isAuthenticatedSourceRequest = await CheckTunnelRequestIsAuthenticatedSourceRequest(context, cluster);
        if (isAuthenticatedSourceRequest)
        {
            return null;
        }
        else
        {
            return Results.Forbid();
        }
#endif
        await Task.CompletedTask;
        return null;

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
        if (!IsClientCertificate(config.TransportAuthentication.Mode))
        {
            return false;
        }
        if (!(config.TransportAuthentication.ClientCertificate is { Length: > 0 } clientCertificateId))
        {
            return false;
        }

        // THINKOF: is this really needed? - since their must be a matching certificate
        //if (!ValidateCertificateAsync(clientCertificate))
        //{
        //    Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, GetAuthenticationMode(), clientCertificate.Subject);
        //    return false;
        //}

        using var shareCurrentCertificateCollection = _certificateManager.GetCertificateCollection(clientCertificateId);
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
                    Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, GetAuthenticationMode(), clusterCertificate.Subject);
                    return true;
                }
            }

            {
                Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, GetAuthenticationMode(), clientCertificate.Subject);
                return false;
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

#warning use/sync CertificationManager way
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
