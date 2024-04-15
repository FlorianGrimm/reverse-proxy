using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;

using static System.Collections.Specialized.BitVector32;

namespace Yarp.ReverseProxy.Configuration.ConfigProvider;

internal sealed class TunnelConfigProvider : IProxyTunnelConfigProvider, IDisposable
{
    private readonly object _lockObject = new();
    private readonly ILogger<TunnelConfigProvider> _logger;
    private readonly IConfiguration _configuration;
    private TunnelConfigurationSnapshot? _snapshot;
    private CancellationTokenSource? _changeToken;
    private bool _disposed;
    private IDisposable? _subscription;

    public TunnelConfigProvider(
        IConfiguration configuration)
    {
        _logger = NullLogger<TunnelConfigProvider>.Instance;
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public TunnelConfigProvider(
        ILogger<TunnelConfigProvider> logger,
        IConfiguration configuration)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _subscription?.Dispose();
            _changeToken?.Dispose();
            _disposed = true;
        }
    }

    public IProxyTunnelConfig GetTunnelConfig()
    {
        // First time load
        if (_snapshot is null)
        {
            _subscription = ChangeToken.OnChange(_configuration.GetReloadToken, UpdateSnapshot);
            UpdateSnapshot();
        }

        return _snapshot;
    }

    [MemberNotNull(nameof(_snapshot))]
    private void UpdateSnapshot()
    {
        // Prevent overlapping updates, especially on startup.
        lock (_lockObject)
        {
            Log.LoadData(_logger);
            TunnelConfigurationSnapshot newSnapshot;
            try
            {
                newSnapshot = new TunnelConfigurationSnapshot();

                foreach (var section in _configuration.GetSection("TunnelFrontendToBackends").GetChildren())
                {
                    newSnapshot.TunnelFrontendToBackends.Add(CreateTunnelFrontendToBackend(section));
                }

                foreach (var section in _configuration.GetSection("TunnelBackendToFrontends").GetChildren())
                {
                    newSnapshot.TunnelBackendToFrontends.Add(CreateTunnelBackendToFrontend(section));
                }
            }
            catch (Exception ex)
            {
                Log.ConfigurationDataConversionFailed(_logger, ex);

                // Re-throw on the first time load to prevent app from starting.
                if (_snapshot is null)
                {
                    throw;
                }

                return;
            }

            var oldToken = _changeToken;
            _changeToken = new CancellationTokenSource();
            newSnapshot.ChangeToken = new CancellationChangeToken(_changeToken.Token);
            _snapshot = newSnapshot;

            try
            {
                oldToken?.Cancel(throwOnFirstException: false);
            }
            catch (Exception ex)
            {
                Log.ErrorSignalingChange(_logger, ex);
            }
        }
    }

    private static TunnelFrontendToBackendConfig CreateTunnelFrontendToBackend(IConfigurationSection section)
    {
        var transport = section[nameof(TunnelFrontendToBackendConfig.Transport)];
        var normalizedTransport = !string.IsNullOrEmpty(transport) ? transport : "TunnelHttp2";
        return new TunnelFrontendToBackendConfig()
        {
            TunnelId = section.Key,
            Transport = section[nameof(TunnelFrontendToBackendConfig.Transport)] ?? string.Empty,
            Authentication = CreateFrontendToBackendAuthentication(section.GetSection(nameof(TunnelFrontendToBackendConfig.Authentication)))
        };
    }

    private static TunnelFrontendToBackendAuthenticationConfig CreateFrontendToBackendAuthentication(IConfigurationSection section)
    {
        // TODO: certs
        Debug.Assert(section is not null);
        return new TunnelFrontendToBackendAuthenticationConfig();
    }

    private static TunnelBackendToFrontendConfig CreateTunnelBackendToFrontend(IConfigurationSection section)
    {
        return new TunnelBackendToFrontendConfig()
        {
            TunnelId = section.Key,
            RemoteTunnelId = section[nameof(TunnelBackendToFrontendConfig.RemoteTunnelId)] ?? string.Empty,
            Url = section[nameof(TunnelBackendToFrontendConfig.Url)] ?? string.Empty,
            Transport = section[nameof(TunnelBackendToFrontendConfig.Transport)] ?? string.Empty,
            Authentication = CreateBackendToFrontendAuthentication(section.GetSection(nameof(TunnelBackendToFrontendConfig.Authentication)))
        };
    }

    private static TunnelBackendToFrontendAuthenticationConfig CreateBackendToFrontendAuthentication(IConfigurationSection section)
    {
        // TODO: certs
        Debug.Assert(section is not null);
        return new TunnelBackendToFrontendAuthenticationConfig();
    }

    private static class Log
    {
        private static readonly Action<ILogger, Exception> _errorSignalingChange = LoggerMessage.Define(
            LogLevel.Error,
            EventIds.ErrorSignalingChange,
            "An exception was thrown from the change notification.");

        private static readonly Action<ILogger, Exception?> _loadData = LoggerMessage.Define(
            LogLevel.Information,
            EventIds.LoadData,
            "Loading proxy data from config.");

        private static readonly Action<ILogger, Exception> _configurationDataConversionFailed = LoggerMessage.Define(
            LogLevel.Error,
            EventIds.ConfigurationDataConversionFailed,
            "Configuration data conversion failed.");

        public static void ErrorSignalingChange(ILogger logger, Exception exception)
        {
            _errorSignalingChange(logger, exception);
        }

        public static void LoadData(ILogger logger)
        {
            _loadData(logger, null);
        }

        public static void ConfigurationDataConversionFailed(ILogger logger, Exception exception)
        {
            _configurationDataConversionFailed(logger, exception);
        }
    }
}
