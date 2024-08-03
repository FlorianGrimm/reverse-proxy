// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

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

namespace Yarp.ReverseProxy.Tunnel;

internal sealed class TunnelAuthenticationCertificate
    : ITunnelAuthenticationService
    , IClusterChangeListener
    , IDisposable
{
    public const string AuthenticationName = "ClientCertificate";
    public const string CookieName = "YarpTunnelAuth";

    private readonly TunnelAuthenticationCertificateOptions _options;
    private readonly ILazyRequiredServiceResolver<ProxyConfigManager> _proxyConfigManagerLazy;
    private readonly ITunnelAuthenticationCookieService _cookieService;
    private readonly ICertificateConfigLoader _certificateConfigLoader;
    private readonly CertificatePathWatcher _certificatePathWatcher;
    private readonly ILogger _logger;
    private IDisposable? _unregisterCertificatePathWatcher;
    private ImmutableDictionary<string, X509Certificate2>? _validCertificatesByThumbprint;
    private ImmutableDictionary<string, X509Certificate2>? _validCertificatesByCluster;

    public TunnelAuthenticationCertificate(
        IOptions<TunnelAuthenticationCertificateOptions> options,
        ILazyRequiredServiceResolver<ProxyConfigManager> proxyConfigManagerLazy,
        ITunnelAuthenticationCookieService cookieService,
        ICertificateConfigLoader certificateConfigLoader,
        CertificatePathWatcher certificatePathWatcher,
        ILogger<TunnelAuthenticationCertificate> logger
        )
    {
        _options = options.Value;
        _proxyConfigManagerLazy = proxyConfigManagerLazy;
        _cookieService = cookieService;
        _certificateConfigLoader = certificateConfigLoader;
        _certificatePathWatcher = certificatePathWatcher;
        _logger = logger;

        _unregisterCertificatePathWatcher = ChangeToken.OnChange(
            _certificatePathWatcher.GetChangeToken,
            () => ClearCertificateCache()
            );
    }

    public string GetAuthenticationName() => AuthenticationName;

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

    public void MapAuthentication(IEndpointRouteBuilder endpoints, RouteHandlerBuilder conventionBuilder, string pattern)
    {
        // add a second endpoint for the same pattern but for GET not POST.
        //endpoints.MapGet(pattern, MapGetAuth); // .RequireAuthorization(PolicyName);
    }

    /*
        Get and validate the Windows authenticated User
        and add cookie "YarpTunnelAuth" in the response.
     */
    private async Task MapGetAuth(HttpContext context)
    {
        var identity = context.User.Identity;
        if (context.GetRouteValue("clusterId") is string clusterId
            && _proxyConfigManagerLazy.GetService().TryGetCluster(clusterId, out var cluster)
            && cluster.Model.Config.IsTunnelTransport()
            )
        {
            context.Response.StatusCode = 200;

            ClaimsPrincipal principal = new(new ClaimsIdentity("Tunnel", "Tunnel", null));
            var auth = _cookieService.NewCookie(principal);
            context.Response.Cookies.Append(CookieName, auth, new CookieOptions()
            {
                Domain = context.Request.Host.Host,
                Path = context.Request.Path,
                IsEssential = true,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict
            });
            await context.Response.WriteAsync("OK");
        }
        else
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
        }
        await context.Response.CompleteAsync();
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

        var validCertificatesByCluster = _validCertificatesByCluster;
        var validCertificatesByThumbprint = _validCertificatesByThumbprint;
        // ensure the certificates are loaded
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

        // trouble loading?
        if (validCertificatesByThumbprint is null)
        {
            _logger.LogInformation("validCertificatesByThumbprint is null");
            result = false;
        }
        // is their a config for the cert?
        else if (!validCertificatesByThumbprint.TryGetValue(certificate.Thumbprint, out var foundCertificate))
        {
            _logger.LogInformation("validCertificatesByThumbprint:{Thumbprint} is invalid.", certificate.Thumbprint.ToString());
            result = false;
        }
        else
        {
            if (result)
            {
                // is the thumbprint matches this checks for SerialNumber
                result = foundCertificate.Equals(certificate);
                if (!result)
                {
                    _logger.LogInformation("found Certificate:{foundThumbprint} not the configered. {configeredThumbprint}", foundCertificate.Thumbprint.ToString(), certificate.Thumbprint.ToString());
                }
            }
        }

        if (_options.IsCertificateValid is { } isCertificateValid)
        {
            result = isCertificateValid(certificate, chain, sslPolicyErrors, result);
            _logger.LogInformation("Custom IsCertificateValid {result}", result);
            return result;
        }
        else
        {
            _logger.LogInformation("ClientCertificateValidation {result}", result);
            return result;
        }
    }

    private (ImmutableDictionary<string, X509Certificate2> validCertificatesByThumbprint, ImmutableDictionary<string, X509Certificate2> validCertificatesByCluster) LoadCertificates()
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
                // TODO: does this work??
                // var (certificate, clientCertificateCollection) = _certificateConfigLoader.LoadCertificateNoPrivateKey(clientCertificate, cluster.ClusterId);
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

    public IResult? CheckTunnelRequestIsAuthenticated(HttpContext context, ClusterState cluster)
    {
        if (context.User.Identity is not ClaimsIdentity identity)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "no context.User.Identity");
            return Results.StatusCode(401);
        }
        if (!identity.IsAuthenticated)
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "not context.User.Identity.IsAuthenticated");
            return Results.StatusCode(401);
        }
        if (!(string.Equals(
            identity.AuthenticationType,
            "Certificate" /* = Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationDefaults.AuthenticationScheme */,
            System.StringComparison.Ordinal)))
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, "not AuthenticationType");
            return Results.StatusCode(401);
        }

        var validCertificatesByCluster = _validCertificatesByCluster;
        var validCertificatesByThumbprint = _validCertificatesByThumbprint;
        // ensure the certificates are loaded
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
            return Results.StatusCode(401);
        }

        if (!validCertificatesByCluster.TryGetValue(cluster.ClusterId, out var certificate))
        {
            _logger.LogWarning("validCertificatesByCluster {ClusterId} not found.", cluster.ClusterId);
            return Results.StatusCode(401);
        }

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
            Log.ClusterAuthenticationSuccess(_logger, cluster.ClusterId, AuthenticationName, certificate.Subject);
            return default;
        }
        else
        {
            Log.ClusterAuthenticationFailed(_logger, cluster.ClusterId, AuthenticationName, certificate.Subject);
            return Results.StatusCode(401);
        }
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

    ~TunnelAuthenticationCertificate()
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
    }
}
