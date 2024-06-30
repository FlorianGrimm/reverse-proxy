// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Yarp.ReverseProxy.Management;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Utilities;

namespace Yarp.ReverseProxy.Tunnel;
internal sealed class TunnelAuthenticationCertificate
    : ITunnelAuthenticationConfigService
    , IClusterChangeListener
{
    private readonly TunnelAuthenticationCertificateOptions _options;
    private readonly UnShortCitcuitProxyConfigManager _proxyConfigManagerLazy;
    private readonly ICertificateConfigLoader _certificateConfigLoader;
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger<TunnelAuthenticationCertificate> _logger;

    private ImmutableDictionary<string, X509Certificate2>? _ValidCertificatesByThumbprint;
    private ImmutableDictionary<string, X509Certificate2>? _ValidCertificatesByCluster;

    public TunnelAuthenticationCertificate(
        IOptions<TunnelAuthenticationCertificateOptions> options,
        UnShortCitcuitProxyConfigManager proxyConfigManagerLazy,
        ICertificateConfigLoader certificateConfigLoader,
        CertificatePathWatcher certificatePathWatcher,
        ILogger<TunnelAuthenticationCertificate> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _certificateConfigLoader = certificateConfigLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;
    }

    public void ConfigureKestrelServer(KestrelServerOptions kestrelServerOptions)
    {
        kestrelServerOptions.ConfigureHttpsDefaults((HttpsConnectionAdapterOptions httpsOptions) =>
        {
            ConfigureHttpsDefaults(httpsOptions);
        });
    }

    internal void ConfigureHttpsDefaults(HttpsConnectionAdapterOptions httpsOptions)
    {
        httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
        httpsOptions.ClientCertificateValidation = ClientCertificateValidation;
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

    private bool ClientCertificateValidation(X509Certificate2 certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        // REVIEW: is this good engough? 
        var result = (sslPolicyErrors == SslPolicyErrors.None);
        if (!result)
        {
            result = ((sslPolicyErrors & ~_options.IgnoreSslPolicyErrors) == SslPolicyErrors.None);
        }

        var validCertificatesByThumbprint = _ValidCertificatesByThumbprint;
        // ensure the certificates are loaded
        if (validCertificatesByThumbprint is null)
        {
            lock (this)
            {
                if (_ValidCertificatesByThumbprint is null)
                {
                    LoadCertificates();
                    validCertificatesByThumbprint = _ValidCertificatesByThumbprint;
                }
            }
        }

        // trouble loading?
        if (validCertificatesByThumbprint is null)
        {
            return false;
        }

        // is their a config for the cert?
        if (!validCertificatesByThumbprint.TryGetValue(certificate.Thumbprint, out var foundCertificate))
        {
            result = false;
        }
        else
        {
            if (result)
            {
                // is the thumbprint matches this checks for SerialNumber
                result = foundCertificate.Equals(certificate);
            }
        }

        if (_options.IsCertificateValid is { } isCertificateValid)
        {
            result = isCertificateValid(certificate, chain, sslPolicyErrors, result);
        }

        return result;
    }

    private void LoadCertificates()
    {
        var resultCertificatesByThumbprint = new Dictionary<string, X509Certificate2>();
        var resultCertificatesByCluster = new Dictionary<string, X509Certificate2>();
        var proxyConfigManager = _proxyConfigManagerLazy.GetService();
        foreach (var cluster in proxyConfigManager.GetTransportTunnelClusters())
        {
            var config = cluster.Model.Config;
            if (!ClientCertificateLoader.IsClientCertificate(config.Authentication.Mode))
            {
                continue;
            }
            if (config.Authentication.ClientCertificate is { } clientCertificate)
            {
                //TODO: does this work??
                //var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateNoPrivateKey(clientCertificate, cluster.ClusterId);
                var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateWithPrivateKey(clientCertificate, cluster.ClusterId);
                ClientCertificateLoader.DisposeCertificates(clientCertificateCollection, certificate);
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

        _ValidCertificatesByThumbprint = resultCertificatesByThumbprint.ToImmutableDictionary();
        _ValidCertificatesByCluster = resultCertificatesByCluster.ToImmutableDictionary();
    }

    private void ClearCertificateCache()
    {
        lock (this)
        {
            _ValidCertificatesByThumbprint = null;
            _ValidCertificatesByCluster = null;
        }

    }

    public bool CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        var authentication = cluster.Model.Config.Authentication;
        if (!ClientCertificateLoader.IsClientCertificate(authentication.Mode)) { return false; }

        if (context.User.Identity is not ClaimsIdentity identity
            || !identity.IsAuthenticated)
        {
            return false;
        }
        if (!(string.Equals(
            identity.AuthenticationType,
            Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationDefaults.AuthenticationScheme,
            System.StringComparison.Ordinal))) { return false; }

        var validCertificatesByCluster = _ValidCertificatesByCluster;
        // ensure the certificates are loaded
        if (validCertificatesByCluster is null)
        {
            lock (this)
            {
                if (_ValidCertificatesByCluster is null)
                {
                    LoadCertificates();
                    validCertificatesByCluster = _ValidCertificatesByCluster;
                }
            }
        }
        if (validCertificatesByCluster is null) { return false; }

        if (!validCertificatesByCluster.TryGetValue(cluster.ClusterId, out var certificate)) { return false; }

        var identityThumbprint = string.Empty;
        foreach (var claim in identity.Claims)
        {
            if (string.Equals(claim.Type, ClaimTypes.Thumbprint, StringComparison.Ordinal))
            {
                identityThumbprint = claim.Value;
            }
        }

        var result = string.Equals(certificate.Thumbprint, identityThumbprint, System.StringComparison.Ordinal);
        if (result)
        {
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, certificate.Subject);
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, certificate.Subject);
        }
        return result;
    }

    private static class Log
    {
        private static readonly Action<ILogger, string, string, Exception?> _clusterAuthenticationSuccess = LoggerMessage.Define<string, string>(
            LogLevel.Debug,
            EventIds.ClusterAuthenticationSuccess,
            "Cluster {clusterId} Authentication success {subject}.");

        public static void ClusterAuthenticationSuccess(ILogger<TunnelAuthenticationCertificate> logger, string clusterId, string subject)
        {
            _clusterAuthenticationSuccess(logger, clusterId, subject, null);
        }

        private static readonly Action<ILogger, string, string, Exception?> _clusterAuthenticationFailed = LoggerMessage.Define<string, string>(
            LogLevel.Information,
            EventIds.ClusterAuthenticationFailed,
            "Cluster {clusterId} Authentication failed {subject}.");

        public static void ClusterAuthenticationFailed(ILogger<TunnelAuthenticationCertificate> logger, string clusterId, string subject)
        {
            _clusterAuthenticationFailed(logger, clusterId, subject, null);
        }
    }
}

